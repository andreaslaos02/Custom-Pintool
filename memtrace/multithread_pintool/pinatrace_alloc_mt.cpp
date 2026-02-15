//version pou afine ta size=0  na katagrafoun alla ipopsies oti to size=0 einai lathos afou gononde load/stores se afto

//aftos o kwdikas exei filters gia na perni ta alloc tou memcached alla oxi ta load&stores

#include "pin.H"
#include <map>
#include <string>
#include <cstdio>
#include <cstdint>
#include <unistd.h>   // getpid
#include <set>
#include <signal.h>
#include <limits>
#include <cstring>
#include <malloc.h>   // malloc_usable_size
//for ParseProcMaps
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdlib>   // strtoull

using std::string;

// ----------------------------- Knobs -----------------------------    // Gia hooks se malloc/free libc
KNOB<BOOL> KnobUseLibcHooks(KNOB_MODE_WRITEONCE, "pintool",
    "use_libc_hooks", "0", "Also instrument malloc/calloc/realloc/free in libc.");

// --------------------------- Region map --------------------------
struct Region {
    ADDRINT start;  //arxiki diefthinsi
    size_t  size;
    string  tag;
    //bool   freed;
    Region() : start(0), size(0), tag("-")  {} //freed(false)
};

// Global region map (keyed by start)
static std::map<ADDRINT, Region> g_regions;     //taksinomimeno map kata start

// Locks
static PIN_LOCK g_regions_lock;  // protects g_regions
static PIN_LOCK g_events_lock;   // protects events/log/trace global files

// -------------------------- Output files -------------------------
static FILE* logf    = nullptr;          // pintool.log (hooks summary)
static FILE* eventsf = nullptr;          // pinatrace.events (alloc/free only, όπως πριν)
static FILE* tracef  = nullptr;          // pinatrace.out (ΕΝΙΑΙΟ: alloc/free + loads/stores)

static volatile BOOL g_trace_memops = FALSE;   // load/store OFF by default
//static volatile BOOL g_trace_allocs = TRUE;    // alloc/free (συνήθως τα θες πάντα)

// ---------------- Hook dedupe (avoid double-instrumenting aliased RTNs) ----------------
static std::set<ADDRINT> g_hooked_rtn_addrs;
static PIN_LOCK g_hook_lock;


// ------------------- Prototypes for allocator RTNs (IMPORTANT) -------------------
static PROTO g_pMalloc = nullptr;
static PROTO g_pFree = nullptr;
static PROTO g_pCalloc = nullptr;
static PROTO g_pRealloc = nullptr;
static PROTO g_pReallocarray = nullptr;
static PROTO g_pAlignedAlloc = nullptr;
static PROTO g_pMemalign = nullptr;
static PROTO g_pValloc = nullptr;
static PROTO g_pPvalloc = nullptr;
static PROTO g_pPosixMemalign = nullptr;

static VOID InitAllocatorProtosOnce() {
    if (g_pMalloc) return; // already initialized

    g_pMalloc = PROTO_Allocate(
        PIN_PARG(void*), CALLINGSTD_DEFAULT, "malloc",
        PIN_PARG(size_t), PIN_PARG_END());

    g_pFree = PROTO_Allocate(
        PIN_PARG(void), CALLINGSTD_DEFAULT, "free",
        PIN_PARG(void*), PIN_PARG_END());

    g_pCalloc = PROTO_Allocate(
        PIN_PARG(void*), CALLINGSTD_DEFAULT, "calloc",
        PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());

    g_pRealloc = PROTO_Allocate(
        PIN_PARG(void*), CALLINGSTD_DEFAULT, "realloc",
        PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG_END());

    g_pReallocarray = PROTO_Allocate(
        PIN_PARG(void*), CALLINGSTD_DEFAULT, "reallocarray",
        PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());

    g_pAlignedAlloc = PROTO_Allocate(
        PIN_PARG(void*), CALLINGSTD_DEFAULT, "aligned_alloc",
        PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());

    g_pMemalign = PROTO_Allocate(
        PIN_PARG(void*), CALLINGSTD_DEFAULT, "memalign",
        PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());

    g_pValloc = PROTO_Allocate(
        PIN_PARG(void*), CALLINGSTD_DEFAULT, "valloc",
        PIN_PARG(size_t), PIN_PARG_END());

    g_pPvalloc = PROTO_Allocate(
        PIN_PARG(void*), CALLINGSTD_DEFAULT, "pvalloc",
        PIN_PARG(size_t), PIN_PARG_END());

    g_pPosixMemalign = PROTO_Allocate(
        PIN_PARG(int), CALLINGSTD_DEFAULT, "posix_memalign",
        PIN_PARG(void**), PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());
}




// Thread-local context: per-thread state
struct ThreadCtx {
    FILE* out;  // ΔΕΝ χρησιμοποιείται πλέον για αρχεία

    // Pending alloc metadata (για __memtrace_alloc_site)
    bool        hasPendingAlloc;
    size_t      pendingSize;
    const char* pendingTypeTag;
    const char* pendingFunc;
    const char* pendingFile;
    int         pendingLine;
    ADDRINT pendingCallerIp;

    ThreadCtx()
        : out(nullptr),
          hasPendingAlloc(false),
          pendingSize(0),
          pendingTypeTag(nullptr),
          pendingFunc(nullptr),
          pendingFile(nullptr),
          pendingLine(0),
          pendingCallerIp(0)
    {}
};
static TLS_KEY g_tls_key;


/*static inline size_t NormalizeAllocSize(void* p, size_t requested) {
    if (!p) return 0;

    size_t bytes = requested;

    if (bytes == 0) {
        bytes = malloc_usable_size(p);   // glibc
        if (bytes == 0) bytes = 1;       // fallback sentinel
    }

    return bytes;
}

static inline size_t NormalizeAllocSize(void* p, size_t requested) {
    if (!p) return 0;

    size_t usable = malloc_usable_size(p);   // glibc usable bytes
    size_t bytes  = requested;

    // Πάρε το μεγαλύτερο (requested vs usable)
    if (usable > bytes) bytes = usable;

    // Αν και τα δύο είναι 0 (σπάνιο), βάλε 1
    if (bytes == 0) bytes = 1;

    return bytes;
}*/

static inline size_t NormalizeAllocSize(void* p, size_t requested) {
    if (!p) return 0;

    // glibc usable size (real chunk capacity)
    size_t usable = malloc_usable_size(p);

    // Αν για κάποιο λόγο δεν παίξει, fallback
    if (usable == 0) {
        if (requested == 0) return 1;
        return requested;
    }

    // Κράτα usable ώστε να μην βγάζεις false OOB λόγω rounding/alignment
    return usable;
}



// Helper gia IMG name
static inline void GetImgFromIp(ADDRINT ip, std::string &imgName, ADDRINT &imgOff)
{
    imgName.clear();
    imgOff = 0;

    if (ip == 0) return;

    PIN_LockClient();
    IMG img = IMG_FindByAddress(ip);
    if (IMG_Valid(img)) {
        imgName = IMG_Name(img);
        imgOff  = ip - IMG_LowAddress(img);
    }
    PIN_UnlockClient();
}

// Helper function gia to GetSourceLocation oste na doume apo pou proerxonde ta frees
static inline void GetSrcFromIp(ADDRINT ip, std::string &file, INT32 &line, INT32 &col)
{
    file.clear();
    line = 0;
    col  = 0;

    if (ip == 0) return;

    // Pin doc: in analysis routines, take client lock
    PIN_LockClient();
    PIN_GetSourceLocation(ip, &col, &line, &file);
    PIN_UnlockClient();

    // αν δεν βρει info -> file="" line=0 col=0
}

// -------------------------- Pretty printers (ALLOC/FREE only) --------------------------

// ALLOC
static inline void PrintAlloc(THREADID tid,
    ADDRINT region_start, size_t size, const char* type,
    const char* caller_file, int caller_line,
    const char* caller_img, unsigned long caller_img_off,
    ADDRINT caller_pc)
{
    (void)tid;
    if (!tracef) return;

    fprintf(tracef,
        "[ALLOC]    "
        "Region_start=%p    "
        "Size=%zu   "
        "Type=%s    "
        "Caller=%s:%d   "
        "Caller_IMG=%s+0x%lx    "
        "Caller_PC=%p\n",
        (void*)region_start,
        size,
        type ? type : "?",
        caller_file ? caller_file : "?", caller_line,
        caller_img ? caller_img : "?", caller_img_off,
        (void*)caller_pc
    );
    fflush(tracef);
}

// FREE (known exact region)
static inline void PrintFreeKnown(THREADID tid,
    ADDRINT region_start, size_t region_size, const char* type,
    ADDRINT free_ptr,
    const char* caller_file, int caller_line,
    const char* caller_img, unsigned long caller_img_off,
    ADDRINT caller_pc)
{
    (void)tid;
    if (!tracef) return;

    fprintf(tracef,
        "[FREE]     "
        "Region_start=%p    "
        "Region_Size=%zu    "
        "Type=%s    "
        "Free_ptr=%p    "
        "Caller=%s:%d"
        "Caller_IMG=%s+0x%lx    "
        "Caller_PC=%p\n",
        (void*)region_start,
        region_size,
        type ? type : "?",
        (void*)free_ptr,
        caller_file ? caller_file : "?", caller_line,
        caller_img ? caller_img : "?", caller_img_off,
        (void*)caller_pc
    );
    fflush(tracef);
}

// FREE (unknown)
static inline void PrintFreeUnknown(THREADID tid,
    ADDRINT free_ptr,
    const char* caller_file, int caller_line,
    const char* caller_img, unsigned long caller_img_off,
    ADDRINT caller_pc)
{
    (void)tid;
    if (!tracef) return;

    fprintf(tracef,
        "[FREE - UNKNOWN]   "
        "Free_ptr=%p    "
        "Caller=%s:%d   "
        "Caller_IMG=%s+0x%lx    "
        "Caller_PC=%p\n",
        (void*)free_ptr,
        caller_file ? caller_file : "?", caller_line,
        caller_img ? caller_img : "?", caller_img_off,
        (void*)caller_pc
    );
    fflush(tracef);
}


// Helper: fetch per-thread ctx
static inline ThreadCtx* CTX(THREADID tid) {
    return static_cast<ThreadCtx*>(PIN_GetThreadData(g_tls_key, tid));
}

// ------------------------- Lookup helper -------------------------
static bool FindRegionWithOff(ADDRINT a, Region &out, size_t &off);



// Helper
static bool TryMarkHooked(RTN r)
{
    const ADDRINT a = RTN_Address(r);
    PIN_GetLock(&g_hook_lock, 0);
    bool fresh = g_hooked_rtn_addrs.insert(a).second;
    PIN_ReleaseLock(&g_hook_lock);
    return fresh; // true => first time we see this routine address
}

//helper
static inline std::string BaseSym(std::string n) {
    // κόψε version suffix: malloc@@GLIBC_2.2.5 -> malloc
    size_t at = n.find('@');
    if (at != std::string::npos) n = n.substr(0, at);

    // κόψε common glibc prefixes: __GI___libc_malloc -> __libc_malloc
    const std::string gi = "__GI_";
    if (n.rfind(gi, 0) == 0) n = n.substr(gi.size());

    return n;
}

static inline bool IsPltStub(const std::string& raw) {
    // π.χ. "malloc@plt", "free@plt"
    return raw.find("@plt") != std::string::npos;
}

// ----------------------Helper gia overlap detaction -----------------
static bool OverlapsLiveRegion_Locked(ADDRINT newStart, size_t newSize, Region &overlap) {
    if (newStart == 0 || newSize == 0) return false;

    ADDRINT newEnd = newStart + (ADDRINT)newSize;
    if (newEnd < newStart) {
        // overflow
        overlap.start = newStart;
        overlap.size  = newSize;
        overlap.tag   = "ALLOC_OVERFLOW";
        return true;
    }

    auto it = g_regions.lower_bound(newStart);

    // Check previous region
    if (it != g_regions.begin()) {
        auto prev = it; --prev;
        const Region &r = prev->second;
        ADDRINT rEnd = r.start + (ADDRINT)r.size;
        if (rEnd > newStart) { // overlap
            overlap = r;
            return true;
        }
    }

    // Check current region
    if (it != g_regions.end()) {
        const Region &r = it->second;
        if (r.start < newEnd) { // overlap
            overlap = r;
            return true;
        }
    }

    return false;
}

static VOID ParseProcMaps()
{
    std::ifstream in("/proc/self/maps");
    if (!in.is_open()) {
        PIN_GetLock(&g_events_lock, 0);
        if (logf) { fprintf(logf, "[ParseProcMaps] failed to open /proc/self/maps\n"); fflush(logf); }
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    std::string line;
    size_t added = 0, skipped = 0;

    PIN_GetLock(&g_regions_lock, 0);

    while (std::getline(in, line)) {
        // Format:
        // start-end perms offset dev inode [pathname]
        //
        // Example:
        // 7f0bdc000000-7f0bdc021000 rw-p 00000000 00:00 0
        // 55ae734fa000-55ae7351b000 rw-p 00000000 00:00 0 [heap]
        //
        std::istringstream iss(line);
        std::string addr, perms, offset, dev, inode;
        std::string pathname;

        if (!(iss >> addr >> perms >> offset >> dev >> inode)) {
            skipped++;
            continue;
        }

        // rest of line (optional pathname)
        std::getline(iss, pathname);
        if (!pathname.empty() && pathname[0] == ' ') pathname.erase(0, 1);

        // Parse start-end
        auto dash = addr.find('-');
        if (dash == std::string::npos) { skipped++; continue; }

        std::string start_s = addr.substr(0, dash);
        std::string end_s   = addr.substr(dash + 1);

        ADDRINT start = 0, end = 0;

        char* e1 = nullptr;
        char* e2 = nullptr;

        unsigned long long s = strtoull(start_s.c_str(), &e1, 16);
        unsigned long long e = strtoull(end_s.c_str(),   &e2, 16);

        if (!e1 || *e1 != '\0' || !e2 || *e2 != '\0') {
            skipped++;
            continue;
        }

        start = (ADDRINT)s;
        end   = (ADDRINT)e;
        if (end <= start) { skipped++; continue; }
        size_t size = (size_t)(end - start);

        // ---- FILTERING (important) ----
        // We want to seed mostly anonymous/private mmaps that can later be freed by libc
        // and cause UNKNOWN if they happened before hooks.
        //
        // Skip obvious "big general segments" that can create noise:
        // - [heap] and [stack]
        // - file-backed shared libs (pathname with '/')
        //
        // Keep:
        // - anonymous mappings (empty pathname)
        // - special bracket mappings like [anon], [vdso], etc (optional)
        //
        bool is_heap  = (pathname.find("[heap]")  != std::string::npos);
        bool is_stack = (pathname.find("[stack]") != std::string::npos);

        if (is_heap || is_stack) { skipped++; continue; }

        bool file_backed = (!pathname.empty() && pathname[0] == '/');
        if (file_backed) { skipped++; continue; }

        // Optional: keep only writable private mappings (common for malloc mmaps)
        // perms example: "rw-p"
        bool is_private = (perms.size() >= 4 && perms[3] == 'p');
       // bool is_writable = (!perms.empty() && perms.find('w') != std::string::npos);
        if (!(is_private )) {           //&& is_writable
            // If you want more coverage, comment this out.
            skipped++;
            continue;
        }

        // Insert mapping as a region
        Region r;
        r.start = start;
        r.size  = size;

        // Tag for debugging
        if (pathname.empty()) r.tag = "procmap:anon";
        else                  r.tag = "procmap:" + pathname; // e.g. [vdso]

        // Avoid duplicates: if already present, don't override.
        if (g_regions.find(r.start) == g_regions.end()) {
            g_regions[r.start] = r;
            added++;
        } else {
            skipped++;
        }
    }

    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, 0);
    if (logf) {
        fprintf(logf, "[ParseProcMaps] added=%zu skipped=%zu\n", added, skipped);
        fflush(logf);
    }
    if (tracef) {
        fprintf(tracef, "#ParseProcMaps added=%zu skipped=%zu\n", added, skipped);
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}

static BOOL OnSigUsr2(THREADID tid, INT32 sig, CONTEXT* ctxt,
    BOOL hasHandler, const EXCEPTION_INFO* pExceptInfo, VOID* v)
{
(void)tid; (void)sig; (void)ctxt; (void)hasHandler; (void)pExceptInfo; (void)v;

g_trace_memops = !g_trace_memops;

PIN_GetLock(&g_events_lock, 0);
if (logf) {
fprintf(logf, "[CTRL] SIGUSR2 -> g_trace_memops=%d\n", (int)g_trace_memops);
fflush(logf);
}
if (tracef) {
fprintf(tracef, "#CTRL g_trace_memops=%d\n", (int)g_trace_memops);
fflush(tracef);
}
PIN_ReleaseLock(&g_events_lock);

return FALSE; // do not deliver to application
}

// --------------------- Record memory accesses --------------------
/*static VOID RecordRead(THREADID tid, VOID* ip, VOID* ea, UINT32 bytes)
 {
    if (!tracef) return;
    if (!g_trace_memops) return;
    const ADDRINT a = (ADDRINT)ea;
    Region snap;
    size_t off = 0;

    if (!FindRegionWithOff(a, snap, off)) return;

    // Αν for some reason bytes==0, κάνε fallback 1 (σπάνιο αλλά safe)
    if (bytes == 0) bytes = 1;

    //if (off >= snap.size) return;

    //PIN_GetLock(&g_events_lock, tid);
   
    //fprintf(tracef,
      //      "T%u %p: load  base: %p full: %p tag=%s off=%zu\n",
        //    (unsigned)tid, ip,
          //  (void*)snap.start, (void*)a,
            //snap.tag.c_str(), off);
    //PIN_ReleaseLock(&g_events_lock);
    // ΣΩΣΤΟ bounds check:
    if (off + (size_t)bytes > snap.size) {
        // optional: γράψε anomaly για OOB
        PIN_GetLock(&g_events_lock, tid);
        fprintf(tracef,
            "T%u %p: OOB_LOAD base:%p full:%p tag=%s off=%zu size=%u region_size=%zu\n",
            (unsigned)tid, ip,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes, snap.size);
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    PIN_GetLock(&g_events_lock, tid);
    fprintf(tracef,
        "T%u %p: load  base:%p full:%p tag=%s off=%zu size=%u\n",
        (unsigned)tid, ip,
        (void*)snap.start, (void*)a,
        snap.tag.c_str(), off, bytes);
    PIN_ReleaseLock(&g_events_lock);
}*/
static VOID RecordRead(THREADID tid, VOID* ip, VOID* ea, UINT32 bytes)
{
    if (!tracef) return;
    if (!g_trace_memops) return;

    const ADDRINT ipA = (ADDRINT)ip;
    const ADDRINT a   = (ADDRINT)ea;

    Region snap;
    size_t off = 0;
    if (!FindRegionWithOff(a, snap, off)) return;

    if (bytes == 0) bytes = 1;

    // IMG + offset for the *instruction pointer*
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(ipA, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str(); // ή imgName.c_str() για full path

    if (off + (size_t)bytes > snap.size) {
        PIN_GetLock(&g_events_lock, tid);
        fprintf(tracef,
            "T%u %p: OOB_LOAD base:%p full:%p tag=%s off=%zu size=%u region_size=%zu ip_img=%s+0x%lx\n",
            (unsigned)tid, (void*)ipA,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes, snap.size,
            imgC, (unsigned long)imgOff);
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    PIN_GetLock(&g_events_lock, tid);
    fprintf(tracef,
        "T%u %p: load  base:%p full:%p tag=%s off=%zu size=%u ip_img=%s+0x%lx\n",
        (unsigned)tid, (void*)ipA,
        (void*)snap.start, (void*)a,
        snap.tag.c_str(), off, bytes,
        imgC, (unsigned long)imgOff);
    PIN_ReleaseLock(&g_events_lock);
}
/*static VOID RecordWrite(THREADID tid, VOID* ip, VOID* ea) {
    if (!tracef) return;
    if (!g_trace_memops) return;
    const ADDRINT a = (ADDRINT)ea;
    Region snap;
    size_t off = 0;

    if (!FindRegionWithOff(a, snap, off)) return;
    if (off >= snap.size) return;

    PIN_GetLock(&g_events_lock, tid);
     fprintf(tracef,
                "T%u %p: store base: %p full: %p tag=%s off=%zu\n",
                (unsigned)tid, ip,
                (void*)snap.start, (void*)a,
                snap.tag.c_str(), off);
    PIN_ReleaseLock(&g_events_lock);
}*/
/*static VOID RecordWrite(THREADID tid, VOID* ip, VOID* ea, UINT32 bytes) {
    if (!tracef) return;
    if (!g_trace_memops) return;

    const ADDRINT a = (ADDRINT)ea;
    Region snap;
    size_t off = 0;

    if (!FindRegionWithOff(a, snap, off)) return;

    if (bytes == 0) bytes = 1;

    if (off + (size_t)bytes > snap.size) {
        PIN_GetLock(&g_events_lock, tid);
        fprintf(tracef,
            "T%u %p: OOB_STORE base:%p full:%p tag=%s off=%zu size=%u region_size=%zu\n",
            (unsigned)tid, ip,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes, snap.size);
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    PIN_GetLock(&g_events_lock, tid);
    fprintf(tracef,
        "T%u %p: store base:%p full:%p tag=%s off=%zu size=%u\n",
        (unsigned)tid, ip,
        (void*)snap.start, (void*)a,
        snap.tag.c_str(), off, bytes);
    PIN_ReleaseLock(&g_events_lock);
}*/
static VOID RecordWrite(THREADID tid, VOID* ip, VOID* ea, UINT32 bytes)
{
    if (!tracef) return;
    if (!g_trace_memops) return;

    const ADDRINT ipA = (ADDRINT)ip;
    const ADDRINT a   = (ADDRINT)ea;

    Region snap;
    size_t off = 0;
    if (!FindRegionWithOff(a, snap, off)) return;

    if (bytes == 0) bytes = 1;

    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(ipA, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    if (off + (size_t)bytes > snap.size) {
        PIN_GetLock(&g_events_lock, tid);
        fprintf(tracef,
            "T%u %p: OOB_STORE base:%p full:%p tag=%s off=%zu size=%u region_size=%zu ip_img=%s+0x%lx\n",
            (unsigned)tid, (void*)ipA,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes, snap.size,
            imgC, (unsigned long)imgOff);
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    PIN_GetLock(&g_events_lock, tid);
    fprintf(tracef,
        "T%u %p: store base:%p full:%p tag=%s off=%zu size=%u ip_img=%s+0x%lx\n",
        (unsigned)tid, (void*)ipA,
        (void*)snap.start, (void*)a,
        snap.tag.c_str(), off, bytes,
        imgC, (unsigned long)imgOff);
    PIN_ReleaseLock(&g_events_lock);
}

static BOOL ShouldInstrumentIns(INS ins) {

    // Βρίσκουμε σε ποιο image ανήκει η εντολή (exe ή shared lib)
    IMG img = IMG_FindByAddress(INS_Address(ins));
    if (!IMG_Valid(img)) return FALSE;

    // Κάνε trace ΜΟΝΟ το main executable (π.χ. ds_demo, memcached)
    return IMG_IsMainExecutable(img);
}

// ---------------- Instruction instrumentation --------------------
// callbacks gia kathe entoli me mnhmh prin ektelesti kai mono otan ektelestei pragrmatika mnhmh (predicated)
static VOID Instruction(INS ins, VOID*) {
    // Φίλτρο: αγνοούμε libc, libpthread, ld-linux, κτλ.
    if (!ShouldInstrumentIns(ins))
        return;

    const UINT32 n = INS_MemoryOperandCount(ins);
    for (UINT32 i = 0; i < n; ++i) {
        if (INS_MemoryOperandIsRead(ins, i)) {
            /*INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(RecordRead),
                IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA, i, IARG_END);*/
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, AFUNPTR(RecordRead),
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, i,
                    IARG_MEMORYOP_SIZE, i,
                    IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, i)) {
            /*INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(RecordWrite),
                IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA, i, IARG_END);*/
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, AFUNPTR(RecordWrite),
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, i,
                    IARG_MEMORYOP_SIZE, i,
                    IARG_END);
        }
    }
}

// --------------- Dummy-site wrappers (your hooks) ----------------
// These replace __memtrace_alloc_site and __memtrace_free_site
// called from the instrumented program.
// They update the region map and log events.

static VOID CallAllocSite(VOID* ptr, size_t size, const char* type_tag,
    const char* func, const char* file, int line,ADDRINT caller_ip)
{
    THREADID tid = PIN_ThreadId(); // thread που κάνει το alloc

    if (!ptr || size == 0) return;
    const char* tag = type_tag ? type_tag : "?";

    Region r;
r.start = (ADDRINT)ptr;
r.size  = size;
r.tag   = tag;

bool overlapFound = false;
Region ov;

PIN_GetLock(&g_regions_lock, tid);
overlapFound = OverlapsLiveRegion_Locked(r.start, r.size, ov);

if (!overlapFound) {
    g_regions[r.start] = r; // insert live region
}
PIN_ReleaseLock(&g_regions_lock);

if (overlapFound) {
    // γράφουμε anomaly και ΔΕΝ εισάγουμε το νέο region
    PIN_GetLock(&g_events_lock, tid);

    if (tracef) {
        fprintf(tracef,
            "T%u ANOMALY alloc_overlap new_start=%p new_size=%zu new_tag=%s "
            "overlap_start=%p overlap_size=%zu overlap_tag=%s site=%s:%d (%s) pc=%p\n",
            (unsigned)tid,
            (void*)r.start, r.size, r.tag.c_str(),
            (void*)ov.start, ov.size, ov.tag.c_str(),
            file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        fflush(tracef);
    }

    if (eventsf) {
        fprintf(eventsf,
            "ANOMALY alloc_overlap new_start=%p new_size=%zu new_tag=%s "
            "overlap_start=%p overlap_size=%zu overlap_tag=%s site=%s:%d (%s) pc=%p\n",
            (void*)r.start, r.size, r.tag.c_str(),
            (void*)ov.start, ov.size, ov.tag.c_str(),
            file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        fflush(eventsf);
    }

    if (logf) {
        fprintf(logf,
            "[ANOMALY] alloc_overlap new_start=%p new_size=%zu new_tag=%s "
            "overlap_start=%p overlap_size=%zu overlap_tag=%s @%s:%d (%s) pc=%p\n",
            (void*)r.start, r.size, r.tag.c_str(),
            (void*)ov.start, ov.size, ov.tag.c_str(),
            file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        fflush(logf);
    }

    PIN_ReleaseLock(&g_events_lock);
    return; // ΣΗΜΑΝΤΙΚΟ
}

    // Γράψιμο σε trace + events + log με κοινό lock
    PIN_GetLock(&g_events_lock, tid);

    if (tracef) {
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=%s site=%s:%d (%s) pc=%p\n",
                (unsigned)tid,
                (void*)r.start, r.size, r.tag.c_str(),
                file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        fflush(tracef);
    }

    if (logf) {
        fprintf(logf, "[HOOK ALLOC] p=%p size=%zu tag=%s @%s:%d (%s) pc=%p\n",
                ptr, size, tag, file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        fflush(logf);
    }
    if (eventsf) {
        fprintf(eventsf, "alloc start=%p size=%zu tag=%s site=%s:%d (%s) pc=%p\n",
                (void*)r.start, r.size, r.tag.c_str(),
                file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        fflush(eventsf);
    }

    PIN_ReleaseLock(&g_events_lock);
}


static VOID CallFreeSite(VOID* ptr, const char* type_tag,
    const char* func, const char* file, int line,ADDRINT caller_ip)
{
    THREADID tid = PIN_ThreadId();

    if (!ptr) return;
    const char* tag = type_tag ? type_tag : "?";

    bool   known = false;
    Region snap;

    PIN_GetLock(&g_regions_lock, tid);

    auto it = g_regions.find((ADDRINT)ptr);
    if (it != g_regions.end()) {
        snap  = it->second;  // κράτα snapshot πριν σβήσεις
        known = true;
        g_regions.erase(it); // ERASE
    }

    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);

    if (tracef) {
        if (known) {
            fprintf(tracef,
                    "T%u free  start=%p size=%zu tag=%s site=%s:%d (%s) pc=%p\n",
                    (unsigned)tid,
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        } else {
            fprintf(tracef,
                    "T%u free  start=%p tag=%s site=%s:%d (%s) pc=%p UNKNOWN_REGION\n",
                    (unsigned)tid,
                    ptr, tag,
                    file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        }
        fflush(tracef);
    }

    if (logf) {
        fprintf(logf, "[HOOK FREE ] p=%p tag=%s @%s:%d (%s)%s pc=%p\n",
                ptr, tag,
                file ? file : "?", line, func ? func : "?",
                known ? "" : " (UNKNOWN)",(void*)caller_ip) ;
        fflush(logf);
    }
    if (eventsf) {
        if (known) {
            fprintf(eventsf, "free  start=%p size=%zu tag=%s site=%s:%d (%s) pc=%p\n",
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        } else {
            fprintf(eventsf, "free  start=%p tag=%s site=%s:%d (%s) pc=%p\n",
                    ptr, tag,
                    file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        }
        fflush(eventsf);
    }

    PIN_ReleaseLock(&g_events_lock);
}

// BEFORE: κρατάμε τα arguments σε per-thread context
static VOID BeforeAllocSite(THREADID tid,
    VOID* /*ptr_arg*/,
    size_t size,
    const char* type_tag,
    const char* func,
    const char* file,
    int line,ADDRINT caller_ip)
{
    ThreadCtx* tc = CTX(tid);
    if (!tc) return;

    tc->hasPendingAlloc  = true;
    tc->pendingSize      = size;
    tc->pendingTypeTag   = type_tag;
    tc->pendingFunc      = func;
    tc->pendingFile      = file;
    tc->pendingLine      = line;
    tc->pendingCallerIp = caller_ip;
}

// AFTER: παίρνουμε το πραγματικό ptr (return value) και κάνουμε register το region
static VOID AfterAllocSite(THREADID tid, VOID* retptr)
{
    if (!retptr) return; 

    ThreadCtx* tc = CTX(tid);
    if (!tc || !tc->hasPendingAlloc) return;

    // Χρησιμοποιούμε την ήδη υπάρχουσα CallAllocSite για να ενημερώσει g_regions + events + trace
    CallAllocSite(retptr,
                  tc->pendingSize,
                  tc->pendingTypeTag,
                  tc->pendingFunc,
                  tc->pendingFile,
                  tc->pendingLine,
                  tc->pendingCallerIp);

    tc->hasPendingAlloc = false; // cleanup
    tc->pendingCallerIp = 0;    //cleanup
}


// ----------------- Hook your dummy symbols if present ------------
// Vriskoume ta __memtrace_alloc_site kai __memtrace_free_site an yparxoun kai kanoume replace me ta dika mas (callAlloc/FreeSite).
// Scanarei to image gia ta dummy sites.

static VOID HookDummySites(IMG img)
{
    for (SEC s = IMG_SecHead(img); SEC_Valid(s); s = SEC_Next(s)) {
        for (RTN r = SEC_RtnHead(s); RTN_Valid(r); r = RTN_Next(r)) {
            string n = RTN_Name(r);

            // --- Hook για __memtrace_alloc_site --------------------
            if (n.find("__memtrace_alloc_site") != string::npos) {

                PROTO pAlloc = PROTO_Allocate(
                    PIN_PARG(void*),                 // return type (void*)
                    CALLINGSTD_DEFAULT,
                    "__memtrace_alloc_site",
                    PIN_PARG(void*),                // ptr (unused)
                    PIN_PARG(size_t),               // size
                    PIN_PARG(const char*),          // type_tag
                    PIN_PARG(const char*),          // func
                    PIN_PARG(const char*),          // file
                    PIN_PARG(int),                  // line
                    PIN_PARG_END());

                RTN_Open(r);

                // BEFORE: αποθήκευση των arguments σε TLS (ασφαλές εδώ)
                RTN_InsertCall(
                    r, IPOINT_BEFORE, AFUNPTR(BeforeAllocSite),
                    IARG_THREAD_ID,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ptr (δεν το χρησιμοποιούμε)
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // size
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // type_tag
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // func
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // file
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // line
                    IARG_RETURN_IP,
                    IARG_END);

                // AFTER: παίρνουμε το πραγματικό return value (malloc ptr)
                RTN_InsertCall(
                    r, IPOINT_AFTER, AFUNPTR(AfterAllocSite),
                    IARG_THREAD_ID,
                    IARG_PROTOTYPE, pAlloc,
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);

                RTN_Close(r);
                PROTO_Free(pAlloc);

                PIN_GetLock(&g_events_lock, 0);
                if (logf) {
                    fprintf(logf, "[HOOK] __memtrace_alloc_site in %s\n",
                            IMG_Name(img).c_str());
                    fflush(logf);
                }
                PIN_ReleaseLock(&g_events_lock);
            }
                        
            // --- Hook για __memtrace_free_site ---------------------
            else if (n.find("__memtrace_free_site") != string::npos) {

                PROTO pFree = PROTO_Allocate(
                    PIN_PARG(void),                 // return type (void)
                    CALLINGSTD_DEFAULT,
                    "__memtrace_free_site",
                    PIN_PARG(void*),                // ptr
                    PIN_PARG(const char*),          // type_tag
                    PIN_PARG(const char*),          // func
                    PIN_PARG(const char*),          // file
                    PIN_PARG(int),                  // line
                    PIN_PARG_END());

                RTN_Open(r);
                RTN_InsertCall(
                    r, IPOINT_BEFORE, AFUNPTR(CallFreeSite),
                    IARG_PROTOTYPE, pFree,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ptr
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // type_tag
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // func
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // file
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // line
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                PROTO_Free(pFree);

                PIN_GetLock(&g_events_lock, 0);
                if (logf) {
                    fprintf(logf, "[HOOK] __memtrace_free_site in %s\n",
                            IMG_Name(img).c_str());
                    fflush(logf);
                }
                PIN_ReleaseLock(&g_events_lock);
            }
        }
    }
}


// ----------------- Optional glibc malloc/free hooks --------------
// otan energopoihthei to knob use_libc_hooks, kanoume hook ta malloc/calloc/realloc/free

static VOID AfterMalloc(ADDRINT ret, size_t sz, ADDRINT caller_ip) {
    if (!ret ) return;      //|| sz == 0
    THREADID tid = PIN_ThreadId();
    //real size
    size_t bytes = NormalizeAllocSize((void*)ret, sz);

    //debug msg
    PIN_GetLock(&g_events_lock, tid);
    if (logf) {
        std::string imgName; ADDRINT imgOff = 0;
        GetImgFromIp(caller_ip, imgName, imgOff);
        /*fprintf(logf, "[MALLOC HIT] ret=%p sz=%zu caller_pc=%p img=%s+0x%lx\n",
                (void*)ret, sz, (void*)caller_ip,
                imgName.c_str(), (unsigned long)imgOff);*/
                size_t usable_dbg = malloc_usable_size((void*)ret);
                fprintf(logf, "[MALLOC HIT] ret=%p req=%zu usable=%zu caller_pc=%p img=%s+0x%lx\n",
                        (void*)ret, sz, usable_dbg, (void*)caller_ip,
                        imgName.c_str(), (unsigned long)imgOff);
        fflush(logf);
    }
    PIN_ReleaseLock(&g_events_lock);
    //end of debug msg
    // caller source location
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // image name + offset (NEW)
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    PIN_GetLock(&g_regions_lock, tid);
    Region r; r.start = ret; r.size = bytes; r.tag = "heap:malloc";     //r.size =sz;  //θα το αλλάξουμε σε πραγματικό size με βάση το malloc_usable_size
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);
    PIN_GetLock(&g_events_lock, tid);

    // trace (new clean format)
    PrintAlloc(tid,
        (ADDRINT)ret,
        bytes,          //sz
        "heap:malloc",                 // Type
        srcFileC,
        (int)srcLine,
        imgC,
        (unsigned long)imgOff,
        caller_ip
    );

    // eventsf (προαιρετικά: κράτα παλιό format για scripts)
    if (eventsf) {
        /*fprintf(eventsf,
            "alloc start=%p size=%zu tag=heap:malloc site=%s:%d img=%s+0x%lx pc=%p\n",
            (void*)ret, sz,
            srcFileC, (int)srcLine,
            imgC, (unsigned long)imgOff,
            (void*)caller_ip);
        fflush(eventsf);*/
        fprintf(eventsf,
            "alloc start=%p size=%zu tag=heap:malloc site=%s:%d img=%s+0x%lx pc=%p\n",
            (void*)ret, bytes,
            srcFileC, (int)srcLine,
            imgC, (unsigned long)imgOff,
            (void*)caller_ip);
        fflush(eventsf);    
    }

    PIN_ReleaseLock(&g_events_lock);
}

static VOID AfterCalloc(ADDRINT ret, size_t n, size_t sz, ADDRINT caller_ip) {
    //if (!ret || n == 0 || sz == 0) return;
    //size_t bytes = n * sz;
    if (!ret) return;

    size_t bytes = 0;
    if (n != 0 && sz != 0) {
        if (n > (std::numeric_limits<size_t>::max() / sz)) {
            return; // overflow -> μην κάνεις update
        }
        bytes = n * sz;
    } else {
        bytes = 0; // calloc(0, x) ή calloc(x,0) -> bytes 0 αλλά ptr μπορεί να είναι non-null
    }
    bytes = NormalizeAllocSize((void*)ret, bytes);
    THREADID tid = PIN_ThreadId();

    // caller source location
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // image name + offset (NEW)
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    PIN_GetLock(&g_regions_lock, tid);
    Region r; r.start = ret; r.size = bytes; r.tag = "heap:calloc";
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);

    // trace (new clean format)
    PrintAlloc(tid,
        (ADDRINT)ret,
        bytes,
        "heap:calloc",
        srcFileC,
        (int)srcLine,
        imgC,
        (unsigned long)imgOff,
        caller_ip
    );

    // eventsf (keep old format if you want)
    if (eventsf) {
        fprintf(eventsf,
            "alloc start=%p size=%zu tag=heap:calloc site=%s:%d img=%s+0x%lx pc=%p\n",
            (void*)ret, bytes,
            srcFileC, (int)srcLine,
            imgC, (unsigned long)imgOff,
            (void*)caller_ip);
        fflush(eventsf);
    }

    PIN_ReleaseLock(&g_events_lock);
}

static VOID AfterRealloc(ADDRINT ret, ADDRINT oldp, size_t sz, ADDRINT caller_ip) {
    THREADID tid = PIN_ThreadId();

    // caller source location (same for both free(old) + alloc(new))
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // image name + offset (NEW)
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    // old pointer gets freed (semantically)
    if (oldp) {
        bool known = false;
        Region snap;

        PIN_GetLock(&g_regions_lock, tid);
        auto it = g_regions.find(oldp);
        if (it != g_regions.end()) {
            snap = it->second;
            known = true;
            g_regions.erase(it);
        }
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (eventsf) {
            if (known) {
                fprintf(eventsf,
                        "free  start=%p size=%zu tag=%s site=%s:%d img=%s+0x%lx pc=%p\n",
                        (void*)snap.start, snap.size, snap.tag.c_str(),
                        srcFileC, (int)srcLine,
                        imgC, (unsigned long)imgOff,
                        (void*)caller_ip);
            } else {
                fprintf(eventsf,
                        "free  start=%p tag=UNKNOWN site=%s:%d img=%s+0x%lx pc=%p\n",
                        (void*)oldp,
                        srcFileC, (int)srcLine,
                        imgC, (unsigned long)imgOff,
                        (void*)caller_ip);
            }
            fflush(eventsf);
        }
        if (tracef) {
            if (known) {
                        PrintFreeKnown(tid,(ADDRINT)snap.start,snap.size,snap.tag.c_str(),        // Type = tag του region
                            (ADDRINT)oldp,           // Free_ptr
                            srcFileC,(int)srcLine,imgC,(unsigned long)imgOff,caller_ip);
            } else {
                        PrintFreeUnknown(tid,
                            (ADDRINT)oldp,
                            srcFileC,
                            (int)srcLine,
                            imgC,
                            (unsigned long)imgOff,
                            caller_ip
                        );
            }
            //fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }

    // new allocation
    if (ret) {
        size_t bytes = NormalizeAllocSize((void*)ret, sz);
        PIN_GetLock(&g_regions_lock, tid);
        Region r; r.start = ret; r.size = bytes; r.tag = "heap:realloc";
        g_regions[ret] = r;
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (eventsf) {
            fprintf(eventsf,
                    "alloc start=%p size=%zu tag=heap:realloc site=%s:%d img=%s+0x%lx pc=%p\n",
                    (void*)ret, bytes,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
            fflush(eventsf);
        }
        if (tracef) {
           
            PrintAlloc(tid,
                (ADDRINT)ret,
                bytes,
                "heap:realloc",
                srcFileC,
                (int)srcLine,
                imgC,
                (unsigned long)imgOff,
                caller_ip
            );
        }
        PIN_ReleaseLock(&g_events_lock);
    }
}


// reallocarray(old_ptr, nmemb, size) -> new_ptr
static VOID AfterReallocarray(ADDRINT ret, ADDRINT oldp, size_t nmemb, size_t elemsz, ADDRINT caller_ip)
{
    // overflow-safe multiply: bytes = nmemb * elemsz
    size_t bytes = 0;

    if (nmemb != 0 && elemsz != 0) {
        if (nmemb > (std::numeric_limits<size_t>::max() / elemsz)) {
            // overflow: η reallocarray θα αποτύχει (ret==NULL) συνήθως.
            // Δεν κάνουμε update map για να μη διαλύσουμε state.
            // Προαιρετικά μπορείς να γράψεις log/anomaly εδώ.
            return;
        }
        bytes = nmemb * elemsz;
    } else {
        bytes = 0; // reallocarray(...,0,...) => bytes=0 (συμπεριφορά τύπου realloc)
    }

    // Χρησιμοποίησε την ήδη υπάρχουσα λογική σου για realloc
    AfterRealloc(ret, oldp, bytes, caller_ip);
}

static bool FindRegionWithOff(ADDRINT a, Region &out, size_t &off)
{
    bool found = false;
    PIN_GetLock(&g_regions_lock, PIN_ThreadId());
    auto it = g_regions.upper_bound(a);
    if (it != g_regions.begin()) {
        --it;
        const Region &r = it->second;
        ADDRINT end = r.start + (ADDRINT)r.size;
        if (end >= r.start && a >= r.start && a < end) {

       // if (a >= r.start && a < (r.start + r.size)) {
            out = r;
            off = (size_t)(a - r.start);        //return offset here instead of calculatig in RecordRead/Write.
            found = true;
        }
    }
    PIN_ReleaseLock(&g_regions_lock);
    return found;
}

static VOID BeforeFree(ADDRINT p, ADDRINT caller_ip) {
    //claude
    // DEBUG: Log EVERY free attempt
    PIN_GetLock(&g_events_lock, PIN_ThreadId());
    if (logf) {
        //fprintf(logf, "[DEBUG FREE] ptr=%p caller_ip=%p\n", (void*)p, (void*)caller_ip);
        std::string imgName; ADDRINT imgOff=0;
        GetImgFromIp(caller_ip, imgName, imgOff);
        fprintf(logf, "[DEBUG FREE] ptr=%p caller_ip=%p img=%s+0x%lx\n",
             (void*)p, (void*)caller_ip, imgName.c_str(), (unsigned long)imgOff);
        fflush(logf);
    }
    PIN_ReleaseLock(&g_events_lock);
    // End DEBUG

    
    if (!p) return;
    THREADID tid = PIN_ThreadId();

    // ---- Source location (κρατάμε αυτό που είχες) ----
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // ---- Image name + offset (ΝΕΟ) ----
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    bool known_exact = false;
    bool known_inside = false;
    Region snap;
    size_t off = 0;

    PIN_GetLock(&g_regions_lock, tid);

    // 1) exact start
    auto it = g_regions.find(p);
    if (it != g_regions.end()) {
        snap = it->second;
        known_exact = true;
        g_regions.erase(it);
    } else {
        // 2) interior pointer?
        auto it2 = g_regions.upper_bound(p);
        if (it2 != g_regions.begin()) {
            --it2;
            const Region &r = it2->second;
            ADDRINT end = r.start + (ADDRINT)r.size;
            if (p >= r.start && p < end) {
                snap = r;
                off = (size_t)(p - r.start);
                known_inside = true;
                // δεν κάνουμε erase εδώ
            }
        }
    }

    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);

    if (eventsf) {
        if (known_exact) {
            fprintf(eventsf,
                    "free  start=%p size=%zu tag=%s site=%s:%d img=%s+0x%lx pc=%p\n",
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        } else if (known_inside) {
            fprintf(eventsf,
                    "ANOMALY free_interior ptr=%p inside_start=%p inside_size=%zu inside_tag=%s off=%zu site=%s:%d img=%s+0x%lx pc=%p\n",
                    (void*)p, (void*)snap.start, snap.size, snap.tag.c_str(), off,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        } else {
            fprintf(eventsf,
                    "free  start=%p tag=UNKNOWN site=%s:%d img=%s+0x%lx pc=%p\n",
                    (void*)p,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        }
        fflush(eventsf);
    }
//fprintf(tracef, "T%u free  start=%p size=%zu tag=%s site=... pc=%p\n", ...)
    if (tracef) {
        if (known_exact) {
                    PrintFreeKnown(tid,
                        (ADDRINT)snap.start,
                        snap.size,
                        snap.tag.c_str(),    // Type
                        (ADDRINT)p,          // Free_ptr = αυτό που δόθηκε στη free(p)
                        srcFileC,
                        (int)srcLine,
                        imgC,
                        (unsigned long)imgOff,
                        caller_ip
                    );                    
        } else if (known_inside) {
            fprintf(tracef,
                    "T%u ANOMALY free_interior ptr=%p inside_start=%p inside_size=%zu inside_tag=%s off=%zu site=%s:%d img=%s+0x%lx pc=%p\n",
                    (unsigned)tid,
                    (void*)p, (void*)snap.start, snap.size, snap.tag.c_str(), off,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        } else {
                    PrintFreeUnknown(tid,
                        (ADDRINT)p,
                        srcFileC,
                        (int)srcLine,
                        imgC,
                        (unsigned long)imgOff,
                        caller_ip
                    );
        }
        fflush(tracef);
    }

    PIN_ReleaseLock(&g_events_lock);
}

// ---------- Extra libc hooks for better coverage ----------

// aligned_alloc(size_t alignment, size_t size) -> void*
static VOID AfterAlignedAlloc(ADDRINT ret, size_t alignment, size_t sz, ADDRINT caller_ip) {
    (void)alignment;
    AfterMalloc(ret, sz, caller_ip);
}

// memalign(size_t alignment, size_t size) -> void*
static VOID AfterMemalign(ADDRINT ret, size_t alignment, size_t sz, ADDRINT caller_ip) {
    (void)alignment;
    AfterMalloc(ret, sz, caller_ip);
}

// valloc(size_t size) -> void*
static VOID AfterValloc(ADDRINT ret, size_t sz, ADDRINT caller_ip) {
    AfterMalloc(ret, sz, caller_ip);
}

// pvalloc(size_t size) -> void*
static VOID AfterPvalloc(ADDRINT ret, size_t sz, ADDRINT caller_ip) {
    AfterMalloc(ret, sz, caller_ip);
}

// posix_memalign(void** memptr, size_t alignment, size_t size) -> int
static VOID AfterPosixMemalign(INT32 rc, ADDRINT memptr_ptr, size_t alignment, size_t sz, ADDRINT caller_ip) {
    (void)alignment;
    if (rc != 0) return;
    void** memptr = (void**)memptr_ptr;
    if (!memptr) return;
    void* p = *memptr;
    if (!p ) return;    //|| sz == 0
    AfterMalloc((ADDRINT)p, sz, caller_ip);
}

// ---------------- mmap/munmap/mremap hooks (with caller pc) ----------------

static VOID AfterMmap(ADDRINT ret, size_t length, ADDRINT caller_ip)
{
    if (!ret || ret == (ADDRINT)-1 || length == 0) return;
    THREADID tid = PIN_ThreadId();

    // caller source location
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // image name + offset (NEW)
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    PIN_GetLock(&g_regions_lock, tid);
    Region r; r.start = ret; r.size = length; r.tag = "mmap";
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);
    if (eventsf) {
        fprintf(eventsf,
                "alloc start=%p size=%zu tag=mmap site=%s:%d img=%s+0x%lx pc=%p\n",
                (void*)ret, length,
                srcFileC, (int)srcLine,
                imgC, (unsigned long)imgOff,
                (void*)caller_ip);
        fflush(eventsf);
    }
    if (tracef) {
                PrintAlloc(tid,
                    (ADDRINT)ret,
                    length,
                    "mmap",
                    srcFileC,
                    (int)srcLine,
                    imgC,
                    (unsigned long)imgOff,
                    caller_ip
                );
        //fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}
//
static VOID AfterMunmap(INT32 rc, ADDRINT addr, size_t length, ADDRINT caller_ip)
{
    if (rc != 0) return;
    if (!addr || length == 0) return;
    THREADID tid = PIN_ThreadId();

    // caller source location
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // image name + offset (NEW)
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    bool known = false;
    Region snap;

    PIN_GetLock(&g_regions_lock, tid);
    auto it = g_regions.find(addr);
    if (it != g_regions.end()) {
        snap = it->second;
        known = true;
        g_regions.erase(it);
    }
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);
    if (eventsf) {
        if (known) {
            fprintf(eventsf,
                    "free  start=%p size=%zu tag=%s site=%s:%d img=%s+0x%lx pc=%p\n",
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        } else {
            fprintf(eventsf,
                    "free  start=%p tag=UNKNOWN site=%s:%d img=%s+0x%lx pc=%p\n",
                    (void*)addr,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        }
        fflush(eventsf);
    }
    if (tracef) {
        if (known) {
            PrintFreeKnown(tid,
                (ADDRINT)snap.start,
                snap.size,
                snap.tag.c_str(),        // Type = region type/tag
                (ADDRINT)addr,           // Free_ptr = addr passed to munmap(addr, len)
                srcFileC,
                (int)srcLine,
                imgC,
                (unsigned long)imgOff,
                caller_ip
            );
        } else {
            PrintFreeUnknown(tid,
                (ADDRINT)addr,           // Free_ptr
                srcFileC,
                (int)srcLine,
                imgC,
                (unsigned long)imgOff,
                caller_ip
            );
        }
    }
    PIN_ReleaseLock(&g_events_lock);
}

static VOID AfterMremap(ADDRINT ret, ADDRINT oldp, size_t oldsz, size_t newsz, ADDRINT caller_ip)
{
    (void)oldsz;
    THREADID tid = PIN_ThreadId();

    // caller source location
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // image name + offset (NEW)
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    // remove old mapping if we tracked it
    if (oldp) {
        bool known_old = false;
        Region snap_old;

        PIN_GetLock(&g_regions_lock, tid);
        auto it = g_regions.find(oldp);
        if (it != g_regions.end()) {
            snap_old = it->second;
            known_old = true;
            g_regions.erase(it);
        }
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (eventsf) {
            if (known_old) {
                fprintf(eventsf,
                        "free  start=%p size=%zu tag=%s site=%s:%d img=%s+0x%lx pc=%p\n",
                        (void*)snap_old.start, snap_old.size, snap_old.tag.c_str(),
                        srcFileC, (int)srcLine,
                        imgC, (unsigned long)imgOff,
                        (void*)caller_ip);
            } else {
                fprintf(eventsf,
                        "free  start=%p tag=UNKNOWN site=%s:%d img=%s+0x%lx pc=%p\n",
                        (void*)oldp,
                        srcFileC, (int)srcLine,
                        imgC, (unsigned long)imgOff,
                        (void*)caller_ip);
            }
            fflush(eventsf);
        }
        if (tracef) {
            // trace (new clean format) - free old mapping
            if (known_old) {
                PrintFreeKnown(tid,
                    (ADDRINT)snap_old.start,
                    snap_old.size,
                    snap_old.tag.c_str(),     // Region_Type
                    (ADDRINT)oldp,            // Free_ptr = oldp passed to mremap
                    srcFileC,
                    (int)srcLine,
                    imgC,
                    (unsigned long)imgOff,
                    caller_ip
                );
            } else {
                PrintFreeUnknown(tid,
                    (ADDRINT)oldp,            // Free_ptr
                    srcFileC,
                    (int)srcLine,
                    imgC,
                    (unsigned long)imgOff,
                    caller_ip
                );
            }
            //fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }

    // track new mapping
    if (ret && ret != (ADDRINT)-1 && newsz) {
        PIN_GetLock(&g_regions_lock, tid);
        Region r; r.start = ret; r.size = newsz; r.tag = "mremap";
        g_regions[ret] = r;
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (eventsf) {
            fprintf(eventsf,
                    "alloc start=%p size=%zu tag=mremap site=%s:%d img=%s+0x%lx pc=%p\n",
                    (void*)ret, newsz,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
            fflush(eventsf);
        }
        if (tracef) {
            PrintAlloc(tid,
                        (ADDRINT)ret,
                        newsz,
                        "mremap",
                        srcFileC,
                        (int)srcLine,
                        imgC,
                        (unsigned long)imgOff,
                        caller_ip
                    );
            //fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
}



static VOID AfterStrdup(ADDRINT ret, const char* s, ADDRINT caller_ip) {
    if (!ret) return;
    size_t sz = s ? (strlen(s) + 1) : 1;
    AfterMalloc(ret, sz, caller_ip); // reuse
}

static VOID AfterStrndup(ADDRINT ret, const char* s, size_t n, ADDRINT caller_ip) {
    if (!ret) return;
    // strndup allocates up to n chars + '\0'
    size_t actual = 0;
    if (s) {
        // bounded strlen
        while (actual < n && s[actual] != '\0') actual++;
    }
    size_t sz = actual + 1;
    AfterMalloc(ret, sz, caller_ip);
}
//claude:
// brk function
// claude

//enimerwnoume ta malloc/calloc/realloc/free tis libc an to knob einai energopoihmeno.
static VOID HookLibcAllocators(IMG img) {
    if (!KnobUseLibcHooks.Value()) return;
    //if (IMG_Type(img) != IMG_TYPE_SHAREDLIB) return;

    // Προαιρετικό αλλά χρήσιμο: κάνε hook μόνο στη libc
    // (μειώνει θόρυβο αν άλλα libs έχουν "malloc" symbols)
    //const string imgName = IMG_Name(img);
    //if (imgName.find("libc.so") == string::npos) return;

    const string imgName = IMG_Name(img);
    //if (imgName.find("libc.so") == string::npos) return;
    //if (imgName.find("/pin/") != string::npos) return;
    //if (imgName.find("ld-linux") != string::npos) return;
   // if (imgName.find("libpindwarf") != string::npos) return;
    //if (imgName.find("pin") != string::npos && imgName.find("/pin/") != string::npos) return;

     // Hook ΜΟΝΟ σε allocator-related libs για να μην πιάνεις stubs / άσχετα symbols
     bool is_libc     = (imgName.find("libc.so") != string::npos);
     bool is_jemalloc = (imgName.find("jemalloc") != string::npos);
     bool is_tcmalloc = (imgName.find("tcmalloc") != string::npos);
 
     if (!(is_libc || is_jemalloc || is_tcmalloc)) return;
     InitAllocatorProtosOnce();
 

    auto LogHook = [&](const char* what) {
        PIN_GetLock(&g_events_lock, 0);
        if (logf) { fprintf(logf, "[HOOK] %s in %s\n", what, imgName.c_str()); fflush(logf); }
        PIN_ReleaseLock(&g_events_lock);
    };

    /*auto HookAfterRet1 = [&](const char* sym, AFUNPTR fn) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, fn,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };

    auto HookAfterRet2 = [&](const char* sym, AFUNPTR fn) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, fn,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };

    auto HookBefore1 = [&](const char* sym, AFUNPTR fn) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_BEFORE, fn,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };

    

    for (SEC s = IMG_SecHead(img); SEC_Valid(s); s = SEC_Next(s)) {
        for (RTN r = SEC_RtnHead(s); RTN_Valid(r); r = RTN_Next(r)) {
    
            std::string raw = RTN_Name(r);
            if (IsPltStub(raw)) continue;   // <<< ΣΗΜΑΝΤΙΚΟ: μην κάνεις hook malloc@plt/free@plt

            std::string bn  = BaseSym(raw);
    
            // -------- malloc --------
            if (bn == "malloc" || bn == "__libc_malloc" || bn == "je_malloc" || bn == "tc_malloc") {
                if (!TryMarkHooked(r)) continue;
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMalloc),
                    IARG_FUNCRET_EXITPOINT_VALUE,          // ret
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // size
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                LogHook(raw.c_str());
            }
    
            // -------- free --------
            else if (bn == "free" || bn == "__libc_free" || bn == "cfree" || bn == "__libc_cfree" ||
                bn == "je_free" || bn == "tc_free") {
                if (!TryMarkHooked(r)) continue;
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeFree),
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // ptr
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                LogHook(raw.c_str());
            }
    
            // -------- calloc(nmemb,size) --------
            else if (bn == "calloc" || bn == "__libc_calloc" || bn == "je_calloc" || bn == "tc_calloc") {
                if (!TryMarkHooked(r)) continue;
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterCalloc),
                    IARG_FUNCRET_EXITPOINT_VALUE,          // ret
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // nmemb
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // size
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                LogHook(raw.c_str());
            }
    
            // -------- realloc(old,size) --------
            else if (bn == "realloc" || bn == "__libc_realloc" || bn == "je_realloc" || bn == "tc_realloc") {
                if (!TryMarkHooked(r)) continue;
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterRealloc),
                    IARG_FUNCRET_EXITPOINT_VALUE,          // ret
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // old
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // size
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                LogHook(raw.c_str());
            }
            // -------- reallocarray(old, nmemb, size) --------
            else if (bn == "reallocarray" || bn == "__libc_reallocarray" || bn == "je_reallocarray") {
                if (!TryMarkHooked(r)) continue;
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterReallocarray),
                    IARG_FUNCRET_EXITPOINT_VALUE,          // ret
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // oldp
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // nmemb
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // elemsz
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                LogHook(raw.c_str());
            }
            else if (bn == "strdup" || bn == "__strdup" || bn == "__GI___strdup") {
                if (!TryMarkHooked(r)) continue;
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterStrdup),
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                LogHook(raw.c_str());
            }
            else if (bn == "strndup" || bn == "__strndup" || bn == "__GI___strndup") {
                if (!TryMarkHooked(r)) continue;
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterStrndup),
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                LogHook(raw.c_str());
            }
        }
    }*/

    auto HookAfterMallocLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMalloc),
            IARG_PROTOTYPE, g_pMalloc,
            IARG_FUNCRET_EXITPOINT_VALUE,      // ret
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // size
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    
    auto HookBeforeFreeLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeFree),
            IARG_PROTOTYPE, g_pFree,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // ptr
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    
    auto HookAfterCallocLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterCalloc),
            IARG_PROTOTYPE, g_pCalloc,
            IARG_FUNCRET_EXITPOINT_VALUE,      // ret
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // nmemb
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // size
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    
    auto HookAfterReallocLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterRealloc),
            IARG_PROTOTYPE, g_pRealloc,
            IARG_FUNCRET_EXITPOINT_VALUE,      // ret
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // oldp
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // size
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    
    auto HookAfterReallocarrayLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterReallocarray),
            IARG_PROTOTYPE, g_pReallocarray,
            IARG_FUNCRET_EXITPOINT_VALUE,      // ret
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // oldp
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // nmemb
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // elemsz
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    
    auto HookAfterAlignedAllocLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterAlignedAlloc),
            IARG_PROTOTYPE, g_pAlignedAlloc,
            IARG_FUNCRET_EXITPOINT_VALUE,      // ret
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // alignment
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // size
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    
    auto HookAfterMemalignLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMemalign),
            IARG_PROTOTYPE, g_pMemalign,
            IARG_FUNCRET_EXITPOINT_VALUE,      // ret
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // alignment
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // size
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    
    auto HookAfterVallocLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterValloc),
            IARG_PROTOTYPE, g_pValloc,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    
    auto HookAfterPvallocLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterPvalloc),
            IARG_PROTOTYPE, g_pPvalloc,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    
    auto HookAfterPosixMemalignLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterPosixMemalign),
            IARG_PROTOTYPE, g_pPosixMemalign,
            IARG_FUNCRET_EXITPOINT_VALUE,      // rc
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // void** memptr
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // alignment
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // size
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
        return true;
    };

    // --- Bulletproof explicit hooks for common aliases ---
    /*HookAfterRet1("malloc",       AFUNPTR(AfterMalloc));        // ret, size(0), return_ip
    HookAfterRet1("__libc_malloc",AFUNPTR(AfterMalloc));

    HookBefore1 ("free",          AFUNPTR(BeforeFree));         // ptr(0), return_ip
    HookBefore1 ("__libc_free",   AFUNPTR(BeforeFree));
    HookBefore1 ("cfree",         AFUNPTR(BeforeFree));
    HookBefore1 ("__libc_cfree",  AFUNPTR(BeforeFree));

    // extra aliases
    //HookBefore1("cfree",        AFUNPTR(BeforeFree));
    //HookBefore1("__libc_cfree", AFUNPTR(BeforeFree));

    // aligned / other allocators
    HookAfterRet2("aligned_alloc", AFUNPTR(AfterAlignedAlloc));
    HookAfterRet2("memalign",      AFUNPTR(AfterMemalign));
    HookAfterRet1("valloc",        AFUNPTR(AfterValloc));
    HookAfterRet1("pvalloc",       AFUNPTR(AfterPvalloc));

        // jemalloc explicit
        HookAfterRet1("je_malloc",  AFUNPTR(AfterMalloc));
        HookBefore1 ("je_free",     AFUNPTR(BeforeFree));
        HookAfterRet2("je_calloc",  AFUNPTR(AfterCalloc));   // NOTE: je_calloc έχει 2 args (nmemb,size)
        HookAfterRet2("je_realloc", AFUNPTR(AfterRealloc));  // NOTE: je_realloc έχει 2 args (old,size) -> ok με HookAfterRet2? όχι! (δες σημείωση)


        HookBefore1 ("__GI___libc_free", AFUNPTR(BeforeFree));
        HookBefore1 ("__GI_free",        AFUNPTR(BeforeFree));
        HookBefore1 ("__GI___free",      AFUNPTR(BeforeFree));*/

        // ---------------- Deterministic hooks (with PROTOTYPE) ----------------

// malloc aliases
for (const char* sym : {
    "malloc", "__libc_malloc", "__GI___libc_malloc",
    "__GI_malloc"
}) {
    HookAfterMallocLike(sym);
}

// free aliases
for (const char* sym : {
    "free", "__libc_free", "__GI___libc_free",
    "cfree", "__libc_cfree",
    "__GI_free"
}) {
    HookBeforeFreeLike(sym);
}

// calloc aliases
for (const char* sym : {
    "calloc", "__libc_calloc", "__GI___libc_calloc",
    "__GI_calloc"
}) {
    HookAfterCallocLike(sym);
}

// realloc aliases
for (const char* sym : {
    "realloc", "__libc_realloc", "__GI___libc_realloc",
    "__GI_realloc"
}) {
    HookAfterReallocLike(sym);
}

// reallocarray aliases
for (const char* sym : {
    "reallocarray", "__libc_reallocarray", "__GI___libc_reallocarray"
}) {
    HookAfterReallocarrayLike(sym);
}

// aligned_alloc / memalign / valloc / pvalloc
for (const char* sym : {"aligned_alloc", "__GI_aligned_alloc"}) {
    HookAfterAlignedAllocLike(sym);
}
for (const char* sym : {"memalign", "__GI_memalign"}) {
    HookAfterMemalignLike(sym);
}
for (const char* sym : {"valloc", "__GI_valloc"}) {
    HookAfterVallocLike(sym);
}
for (const char* sym : {"pvalloc", "__GI_pvalloc"}) {
    HookAfterPvallocLike(sym);
}

// posix_memalign
for (const char* sym : {"posix_memalign", "__GI_posix_memalign"}) {
    HookAfterPosixMemalignLike(sym);
}

// ---------------- jemalloc explicit symbols ----------------

// je_malloc
for (const char* sym : { "je_malloc" }) {
    HookAfterMallocLike(sym);
}

// je_free
for (const char* sym : { "je_free" }) {
    HookBeforeFreeLike(sym);
}

// je_calloc
for (const char* sym : { "je_calloc" }) {
    HookAfterCallocLike(sym);
}

// je_realloc
for (const char* sym : { "je_realloc" }) {
    HookAfterReallocLike(sym);
}

// je_reallocarray (αν υπάρχει)
for (const char* sym : { "je_reallocarray" }) {
    HookAfterReallocarrayLike(sym);
}

    // posix_memalign returns int, writes pointer to *memptr
  /* {
        RTN r = RTN_FindByName(img, "posix_memalign");
        if (RTN_Valid(r)) {
            if (TryMarkHooked(r)) {
            RTN_Open(r);
            RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterPosixMemalign),
                IARG_FUNCRET_EXITPOINT_VALUE,                 // rc
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,             // void** memptr
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,             // alignment
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,             // size
                IARG_RETURN_IP,
                IARG_END);
            RTN_Close(r);
            LogHook("posix_memalign");
            }
        }
    }*/
    // ---------------- mmap/munmap/mremap hooks ----------------
{
    // mmap variants
    //for (const char* sym : {"mmap", "mmap64", "__mmap"}) {
    for (const char* sym : {"mmap", "mmap64", "__mmap", "__mmap64", "__GI___mmap", "__GI___mmap64"}) {
        RTN r = RTN_FindByName(img, sym);
        if (RTN_Valid(r) && TryMarkHooked(r)) {
            RTN_Open(r);
            // mmap(addr, length, prot, flags, fd, offset) -> ret
            RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMmap),
                IARG_FUNCRET_EXITPOINT_VALUE,          // ret
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // length
                IARG_RETURN_IP,
                IARG_END);
            RTN_Close(r);
            LogHook(sym);
        }
    }

    // munmap variants
    //for (const char* sym : {"munmap", "__munmap"}) {
    for (const char* sym : {"munmap", "__munmap", "__GI___munmap"}) {
        RTN r = RTN_FindByName(img, sym);
        if (RTN_Valid(r) && TryMarkHooked(r)) {
            RTN_Open(r);
            // munmap(addr, length) -> int rc
            RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMunmap),
                IARG_FUNCRET_EXITPOINT_VALUE,          // rc
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // addr
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // length
                IARG_RETURN_IP,
                IARG_END);
            RTN_Close(r);
            LogHook(sym);
        }
    }

    // mremap variants
    //for (const char* sym : {"mremap", "__mremap"}) {
    for (const char* sym : {"mremap", "__mremap", "__GI___mremap"}) {
        RTN r = RTN_FindByName(img, sym);
        if (RTN_Valid(r) && TryMarkHooked(r)) {
            RTN_Open(r);
            // mremap(old_address, old_size, new_size, flags, ...) -> ret
            RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMremap),
                IARG_FUNCRET_EXITPOINT_VALUE,          // ret
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // oldp
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // oldsz
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // newsz
                IARG_RETURN_IP,
                IARG_END);
            RTN_Close(r);
            LogHook(sym);
        }
    }
}

// strdup aliases
for (const char* sym : { "strdup", "__strdup", "__GI___strdup" }) {
    RTN r = RTN_FindByName(img, sym);
    if (RTN_Valid(r) && TryMarkHooked(r)) {
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterStrdup),
            IARG_FUNCRET_EXITPOINT_VALUE,          // ret
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // const char* s
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
    }
}

// strndup aliases
for (const char* sym : { "strndup", "__strndup", "__GI___strndup" }) {
    RTN r = RTN_FindByName(img, sym);
    if (RTN_Valid(r) && TryMarkHooked(r)) {
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterStrndup),
            IARG_FUNCRET_EXITPOINT_VALUE,          // ret
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // const char* s
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // size_t n
            IARG_RETURN_IP,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
    }
}


}

// -------------------------- Image load ---------------------------
// kanume hook tis routines gia ta dummy sites kai gia ta libc malloc/free an einai energopoihmeno to knob.
static VOID ImageLoad(IMG img, VOID*) {
    HookDummySites(img);       // your __memtrace_* if present
    HookLibcAllocators(img);   // optional libc hooks (knob)
}

// ----------------------- Thread lifecycle ------------------------
// ΔΕΝ ανοίγουμε πια per-thread trace files, μόνο TLS context
static VOID ThreadStart(THREADID tid, CONTEXT*, INT32, VOID*) {
    ThreadCtx* tc = new ThreadCtx();
    tc->out = nullptr; // δεν χρησιμοποιείται πλέον
    PIN_SetThreadData(g_tls_key, tc, tid);
}

// kathe thread apodesmevei to thread-local context.
static VOID ThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*) {
    ThreadCtx* tc = CTX(tid);
    if (tc) {
        // den iparxei pleon per-thread file
        delete tc;
        PIN_SetThreadData(g_tls_key, nullptr, tid);
    }
}

// ----------------------------- Fini ------------------------------
// Global fini: κλείνει τα global αρχεία log/events/trace
static VOID Fini(INT32, VOID*) {
    PIN_GetLock(&g_events_lock, 0);
    if (tracef) {
        fprintf(tracef, "#eof\n");
        fclose(tracef);
        tracef = nullptr;
    }
    if (eventsf) {
        fprintf(eventsf, "#eof\n");
        fclose(eventsf);
        eventsf = nullptr;
    }
    if (logf) {
        fclose(logf);
        logf = nullptr;
    }
    if (g_pMalloc) { PROTO_Free(g_pMalloc); g_pMalloc = nullptr; }
if (g_pFree) { PROTO_Free(g_pFree); g_pFree = nullptr; }
if (g_pCalloc) { PROTO_Free(g_pCalloc); g_pCalloc = nullptr; }
if (g_pRealloc) { PROTO_Free(g_pRealloc); g_pRealloc = nullptr; }
if (g_pReallocarray) { PROTO_Free(g_pReallocarray); g_pReallocarray = nullptr; }
if (g_pAlignedAlloc) { PROTO_Free(g_pAlignedAlloc); g_pAlignedAlloc = nullptr; }
if (g_pMemalign) { PROTO_Free(g_pMemalign); g_pMemalign = nullptr; }
if (g_pValloc) { PROTO_Free(g_pValloc); g_pValloc = nullptr; }
if (g_pPvalloc) { PROTO_Free(g_pPvalloc); g_pPvalloc = nullptr; }
if (g_pPosixMemalign) { PROTO_Free(g_pPosixMemalign); g_pPosixMemalign = nullptr; }
    PIN_ReleaseLock(&g_events_lock);
}


// ------------------------------ main -----------------------------
// dilwnei ta call backs kai arxizei to Pin.
// ------------------------------ main -----------------------------
// dilwnei ta call backs kai arxizei to Pin.
int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;

    PIN_InitLock(&g_regions_lock);
    PIN_InitLock(&g_events_lock);
    PIN_InitLock(&g_hook_lock);

    g_tls_key = PIN_CreateThreadDataKey(nullptr);

    // ΝΕΟ: Άνοιξε τα αρχεία ΠΡΙΝ το ParseProcMaps
    logf    = fopen("pintool.log", "w");
    eventsf = fopen("pinatrace.events", "w");
    tracef  = fopen("pinatrace.out", "w");

    if (logf) {
        fprintf(logf, "[START] pid=%d g_trace_memops=%d\n", getpid(), (int)g_trace_memops);
        fflush(logf);
    }
    if (tracef) {
        fprintf(tracef, "#TOOL mytool_version=BASELINE_ONLY_ALLOCFREE\n");
        fprintf(tracef, "#START pid=%d g_trace_memops=%d\n", getpid(), (int)g_trace_memops);
        fflush(tracef);
    }

    // Parse pre-existing allocations (ΜΕΤΑ τα αρχεία)
    ParseProcMaps();

    // Callbacks
    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    PIN_InterceptSignal(SIGUSR2, OnSigUsr2, 0);
    PIN_StartProgram(); // never returns
    return 0;
}