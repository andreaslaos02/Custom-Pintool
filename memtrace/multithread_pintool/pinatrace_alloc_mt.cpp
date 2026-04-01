//version pou afine ta size=0  na katagrafoun alla ipopsies oti to size=0 einai lathos afou gononde load/stores se afto

//aftos o kwdikas exei filters gia na perni ta alloc tou memcached alla oxi ta load&stores
// 
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
//#include <malloc.h>   // malloc_usable_size
//for ParseProcMaps
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdlib>   // strtoull
#include <unordered_map>
#include <utility>
#include <array>

using std::string;

// ----------------------------- Knobs -----------------------------    // Gia hooks se malloc/free libc
KNOB<BOOL> KnobUseLibcHooks(KNOB_MODE_WRITEONCE, "pintool",
    "use_libc_hooks", "0", "Also instrument malloc/calloc/realloc/free in libc.");


// knob gia na anoigokleino to diagnostic log stin GetSrcFromIp()
KNOB<BOOL> KnobSrcDebug(KNOB_MODE_WRITEONCE, "pintool",
    "src_debug", "0", "Enable verbose source-location diagnostics.");

// knob for untracked load/stores
KNOB<BOOL> KnobTraceUntracked(KNOB_MODE_WRITEONCE, "pintool",
    "trace_untracked", "0",
    "Also log load/store accesses that do not belong to any tracked region.");

KNOB<BOOL> KnobMainExeOnly(KNOB_MODE_WRITEONCE, "pintool",
    "main_exe_only", "1",
    "Trace memory accesses only from the main executable.");

KNOB<BOOL> KnobTraceStack(KNOB_MODE_WRITEONCE, "pintool",
    "trace_stack", "1",
    "Also log load/store accesses that belong to tracked stack regions.");

KNOB<BOOL> KnobTraceGlobals(KNOB_MODE_WRITEONCE, "pintool",
    "trace_globals", "1",
    "Also track/load-store log accesses that belong to global image sections (.data, .bss, .got, etc.).");

    
// --------------------------- Region map --------------------------
struct Region {
    ADDRINT start;  //arxiki diefthinsi
    size_t  size;
    string  tag;
    //bool   freed;
    //for load/store caller
    string  alloc_file;
    INT32   alloc_line;
    Region() : start(0), size(0), tag("-"), alloc_file("?"), alloc_line(0)  {} //freed(false)
};

// Global region map (keyed by start)
static std::map<ADDRINT, Region> g_regions;     //taksinomimeno map kata start

// Per-thread stack regions
static std::unordered_map<THREADID, Region> g_stack_regions;

// Locks
static PIN_LOCK g_regions_lock;  // protects g_regions
static PIN_LOCK g_events_lock;   // protects events/log/trace global files

static PIN_LOCK g_stack_lock;    // protects g_stack_regions

// -------------------------- Output files -------------------------
static FILE* g_logf    = nullptr;          // pintool.log (hooks summary)
static FILE* eventsf = nullptr;          // pinatrace.events (alloc/free only, όπως πριν)
static FILE* tracef  = nullptr;          // pinatrace.out (ΕΝΙΑΙΟ: alloc/free + loads/stores)

static volatile BOOL g_trace_memops = FALSE;   // load/store OFF by default
//static volatile BOOL g_trace_allocs = TRUE;    // alloc/free (συνήθως τα θες πάντα)

// ---------------- Hook dedupe (avoid double-instrumenting aliased RTNs) ----------------
static std::set<ADDRINT> g_hooked_rtn_addrs;
static PIN_LOCK g_hook_lock;

//Global counters gia symbols_29/3
/*static std::unordered_map<std::string, UINT64> g_installed_symbols;
static std::unordered_map<std::string, UINT64> g_called_symbols;
static PIN_LOCK g_stats_lock;*/

// ---------------------- Source resolve cache ----------------------
struct SrcLoc {
    std::string file;
    INT32 line;
    INT32 col;

    SrcLoc() : file(), line(0), col(0) {}
    SrcLoc(const std::string& f, INT32 l, INT32 c) : file(f), line(l), col(c) {}
};

static std::unordered_map<std::string, SrcLoc> g_src_cache;
static PIN_LOCK g_src_cache_lock;

static inline std::string MakeSrcCacheKey(const std::string& imgPath, ADDRINT imgOff)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s|0x%lx", imgPath.c_str(), (unsigned long)imgOff);
    return std::string(buf);
}

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

static AFUNPTR g_origCalloc = nullptr;
static AFUNPTR g_origRealloc = nullptr;

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

// Adding thread role to the thread context, so we can filter events based on it (πχ μόνο worker threads)
enum ThreadRole {
    ROLE_UNKNOWN = 0,
    ROLE_WORKER,
    ROLE_OTHER
};

static inline const char* ThreadRoleStr(ThreadRole r)
{
    switch (r) {
        case ROLE_WORKER: return "WORKER";
        case ROLE_OTHER:  return "OTHER";
        default:          return "UNKNOWN";
    }
}


// Thread-local context: per-thread state
struct ThreadCtx {
    FILE* out;  // ΔΕΝ χρησιμοποιείται πλέον για αρχεία
    int inCalloc;
    int inRealloc;
    static constexpr UINT64 kMagic = 0xC0FFEE1234ABCDEFULL;
    UINT64 magic;
    THREADID owner_tid;
    // gia na kathorisw to working thread
    ThreadRole role;
    pid_t os_tid;
    
    // Pending alloc metadata (για __memtrace_alloc_site)
    bool        hasPendingAlloc;
    size_t      pendingSize;
    const char* pendingTypeTag;
    const char* pendingFunc;
    const char* pendingFile;
    int         pendingLine;
    ADDRINT pendingCallerIp;

        // ---------------- pending libc allocator args (BEFORE->AFTER) ----------------
        bool   hasPendingMalloc;
        size_t pendingMallocSize;
        ADDRINT pendingMallocCallerIp;

        struct PendingCalloc {
            size_t  n;
            size_t  sz;
            ADDRINT callerIp;
            UINT64 seq;
        };
        UINT64 callocSeq;

        static constexpr int kCallocStackMax = 64;
        PendingCalloc pendingCallocStack[kCallocStackMax];
        int pendingCallocTop; // 0..kCallocStackMax
    
        bool   hasPendingRealloc;
        ADDRINT pendingReallocOldp;
        size_t pendingReallocSz;
        ADDRINT pendingReallocCallerIp;
    
        bool   hasPendingReallocarray;
        ADDRINT pendingReallocarrayOldp;
        size_t pendingReallocarrayNmemb;
        size_t pendingReallocarrayElemsz;
        ADDRINT pendingReallocarrayCallerIp;
    
        // (προαιρετικά αλλά καλό) mmap/munmap/mremap
        bool   hasPendingMmap;
        size_t pendingMmapLen;
        ADDRINT pendingMmapCallerIp;
    
        bool   hasPendingMunmap;
        ADDRINT pendingMunmapAddr;
        size_t pendingMunmapLen;
        ADDRINT pendingMunmapCallerIp;
    
        bool   hasPendingMremap;
        ADDRINT pendingMremapOldp;
        size_t pendingMremapOldsz;
        size_t pendingMremapNewsz;
        ADDRINT pendingMremapCallerIp;

static inline bool CallocPush(ThreadCtx* tc, size_t n, size_t sz, ADDRINT ip, UINT64& outSeq)
{
    if (tc->pendingCallocTop >= ThreadCtx::kCallocStackMax) return false;
    outSeq = ++tc->callocSeq;
    tc->pendingCallocStack[tc->pendingCallocTop] =
        ThreadCtx::PendingCalloc{ n, sz, ip, outSeq };
    tc->pendingCallocTop++; // increment AFTER write (deterministic)
    return true;
}

static inline bool CallocPop(ThreadCtx* tc, ThreadCtx::PendingCalloc& out)
{
    if (tc->pendingCallocTop <= 0) return false;
    tc->pendingCallocTop--;            // decrement BEFORE read (deterministic)
    out = tc->pendingCallocStack[tc->pendingCallocTop];
    return true;
}
    ThreadCtx()
        :out(nullptr),
        inCalloc(0),
        inRealloc(0),
          
         magic(kMagic),
         owner_tid(INVALID_THREADID),
         role(ROLE_UNKNOWN),
         os_tid(0),
          
          hasPendingAlloc(false),
          pendingSize(0),
          pendingTypeTag(nullptr),
          pendingFunc(nullptr),
          pendingFile(nullptr),
          pendingLine(0),
          pendingCallerIp(0),

          

          hasPendingMalloc(false),
          pendingMallocSize(0),
          pendingMallocCallerIp(0),

          callocSeq(0),
          /*hasPendingCalloc(false),
          pendingCallocN(0),
          pendingCallocSz(0),
          pendingCallocCallerIp(0),*/

          pendingCallocTop(0),

          hasPendingRealloc(false),
          pendingReallocOldp(0),
          pendingReallocSz(0),
          pendingReallocCallerIp(0),

          hasPendingReallocarray(false),
          pendingReallocarrayOldp(0),
          pendingReallocarrayNmemb(0),
          pendingReallocarrayElemsz(0),
          pendingReallocarrayCallerIp(0),

          hasPendingMmap(false),
          pendingMmapLen(0),
          pendingMmapCallerIp(0),

          hasPendingMunmap(false),
          pendingMunmapAddr(0),
          pendingMunmapLen(0),
          pendingMunmapCallerIp(0),

          hasPendingMremap(false),
          pendingMremapOldp(0),
          pendingMremapOldsz(0),
          pendingMremapNewsz(0),
          pendingMremapCallerIp(0)
    {}
};

static TLS_KEY g_tls_key;

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

static inline bool ResolveSrcWithAddr2line(const std::string& imgPath,
    ADDRINT imgOff,
    std::string& file,
    INT32& line,
    INT32& col)
{
file.clear();
line = 0;
col  = 0;

if (imgPath.empty()) return false;

// 1) cache lookup
const std::string key = MakeSrcCacheKey(imgPath, imgOff);

PIN_GetLock(&g_src_cache_lock, 0);
auto it = g_src_cache.find(key);
if (it != g_src_cache.end()) {
file = it->second.file;
line = it->second.line;
col  = it->second.col;
PIN_ReleaseLock(&g_src_cache_lock);
return !file.empty() && line > 0;
}
PIN_ReleaseLock(&g_src_cache_lock);

// 2) external resolve
// Χρησιμοποιούμε image-relative offset, όχι absolute runtime PC
char cmd[4096];
snprintf(cmd, sizeof(cmd),
"addr2line -f -C -e \"%s\" 0x%lx 2>/dev/null",
imgPath.c_str(), (unsigned long)imgOff);

FILE* fp = popen(cmd, "r");
if (!fp) return false;

char funcbuf[2048];
char filebuf[4096];

funcbuf[0] = '\0';
filebuf[0] = '\0';

if (!fgets(funcbuf, sizeof(funcbuf), fp)) {
pclose(fp);
return false;
}
if (!fgets(filebuf, sizeof(filebuf), fp)) {
pclose(fp);
return false;
}
pclose(fp);

// trim trailing newline
auto trim_newline = [](char* s) {
size_t n = strlen(s);
while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r')) {
s[n-1] = '\0';
--n;
}
};

trim_newline(funcbuf);
trim_newline(filebuf);

// αναμενόμενο format: /path/file.c:123  ή  ??:?
if (strcmp(filebuf, "??:?") == 0 || strcmp(filebuf, "??:0") == 0 || filebuf[0] == '\0') {
// cache negative result για να μην ξανακαλείται συνέχεια
PIN_GetLock(&g_src_cache_lock, 0);
g_src_cache[key] = SrcLoc("", 0, 0);
PIN_ReleaseLock(&g_src_cache_lock);
return false;
}

char* colon = strrchr(filebuf, ':');
if (!colon) {
PIN_GetLock(&g_src_cache_lock, 0);
g_src_cache[key] = SrcLoc("", 0, 0);
PIN_ReleaseLock(&g_src_cache_lock);
return false;
}

*colon = '\0';
const char* lineStr = colon + 1;
long parsedLine = strtol(lineStr, nullptr, 10);
if (parsedLine <= 0) {
PIN_GetLock(&g_src_cache_lock, 0);
g_src_cache[key] = SrcLoc("", 0, 0);
PIN_ReleaseLock(&g_src_cache_lock);
return false;
}

file = filebuf;
line = (INT32)parsedLine;
col  = 0;

PIN_GetLock(&g_src_cache_lock, 0);
g_src_cache[key] = SrcLoc(file, line, col);
PIN_ReleaseLock(&g_src_cache_lock);

return true;
}


static inline void GetSrcFromIp(ADDRINT ip, std::string &file, INT32 &line, INT32 &col)
{
    file.clear();
    line = 0;
    col  = 0;

    if (ip == 0) {
        if (KnobSrcDebug.Value() && g_logf) {
            PIN_GetLock(&g_events_lock, 0);
            fprintf(g_logf, "[SRCDBG] ip=0x0 -> skip\n");
            fflush(g_logf);
            PIN_ReleaseLock(&g_events_lock);
        }
        return;
    }

    std::string imgName;
    ADDRINT imgOff = 0;

    // ------------------------------------------------------------
    // 1) Βρες image + offset για το exact ip apo pin API
    // ------------------------------------------------------------
    PIN_LockClient();
    IMG img = IMG_FindByAddress(ip);
    if (IMG_Valid(img)) {
        imgName = IMG_Name(img);
        imgOff  = ip - IMG_LowAddress(img);
    }
    PIN_UnlockClient();

    // ------------------------------------------------------------
    // 2) Πρώτη προσπάθεια με Pin API στο exact ip
    // ------------------------------------------------------------
    PIN_LockClient();
    PIN_GetSourceLocation(ip, &col, &line, &file);
    PIN_UnlockClient();

    if (!file.empty() && line > 0) {
        if (KnobSrcDebug.Value() && g_logf) {
            PIN_GetLock(&g_events_lock, 0);
            fprintf(g_logf,
                    "[SRCDBG] ip=%p img=%s off=0x%lx -> PIN exact -> %s:%d col=%d\n",
                    (void*)ip,
                    imgName.empty() ? "?" : imgName.c_str(),
                    (unsigned long)imgOff,
                    file.c_str(),
                    (int)line,
                    (int)col);
            fflush(g_logf);
            PIN_ReleaseLock(&g_events_lock);
        }
        return;
    }

    // ------------------------------------------------------------
    // 3) Δεύτερη προσπάθεια με Pin API στο ip-1
    //    Χρήσιμο γιατί πολλές φορές caller_ip είναι return address
    // ------------------------------------------------------------
    if (ip > 0) {
        std::string file2;
        INT32 line2 = 0, col2 = 0;

        PIN_LockClient();
        PIN_GetSourceLocation(ip - 1, &col2, &line2, &file2);
        PIN_UnlockClient();

        if (!file2.empty() && line2 > 0) {
            file = file2;
            line = line2;
            col  = col2;

            if (KnobSrcDebug.Value() && g_logf) {
                PIN_GetLock(&g_events_lock, 0);
                fprintf(g_logf,
                        "[SRCDBG] ip=%p img=%s off=0x%lx -> PIN ip-1 -> %s:%d col=%d\n",
                        (void*)ip,
                        imgName.empty() ? "?" : imgName.c_str(),
                        (unsigned long)imgOff,
                        file.c_str(),
                        (int)line,
                        (int)col);
                fflush(g_logf);
                PIN_ReleaseLock(&g_events_lock);
            }
            return;
        }
    }

    // ------------------------------------------------------------
    // 4) Fallback με addr2line στο exact image-relative offset
    // ------------------------------------------------------------
    if (!imgName.empty()) {
        if (ResolveSrcWithAddr2line(imgName, imgOff, file, line, col)) {
            if (KnobSrcDebug.Value() && g_logf) {
                PIN_GetLock(&g_events_lock, 0);
                fprintf(g_logf,
                        "[SRCDBG] ip=%p img=%s off=0x%lx -> ADDR2LINE exact -> %s:%d\n",
                        (void*)ip,
                        imgName.c_str(),
                        (unsigned long)imgOff,
                        file.c_str(),
                        (int)line);
                fflush(g_logf);
                PIN_ReleaseLock(&g_events_lock);
            }
            return;
        }
    }

    // ------------------------------------------------------------
    // 5) Τελική προσπάθεια: addr2line στο ip-1 offset
    // ------------------------------------------------------------
    if (ip > 0) {
        std::string imgName2;
        ADDRINT imgOff2 = 0;

        PIN_LockClient();
        IMG img2 = IMG_FindByAddress(ip - 1);
        if (IMG_Valid(img2)) {
            imgName2 = IMG_Name(img2);
            imgOff2  = (ip - 1) - IMG_LowAddress(img2);
        }
        PIN_UnlockClient();

        if (!imgName2.empty() && ResolveSrcWithAddr2line(imgName2, imgOff2, file, line, col)) {
            if (KnobSrcDebug.Value() && g_logf) {
                PIN_GetLock(&g_events_lock, 0);
                fprintf(g_logf,
                        "[SRCDBG] ip=%p img=%s off=0x%lx -> ADDR2LINE ip-1 -> %s:%d\n",
                        (void*)ip,
                        imgName2.c_str(),
                        (unsigned long)imgOff2,
                        file.c_str(),
                        (int)line);
                fflush(g_logf);
                PIN_ReleaseLock(&g_events_lock);
            }
            return;
        }
    }

    // failed
    if (KnobSrcDebug.Value() && g_logf) {
        PIN_GetLock(&g_events_lock, 0);
        fprintf(g_logf,
                "[SRCDBG] ip=%p img=%s off=0x%lx -> unresolved\n",
                (void*)ip,
                imgName.empty() ? "?" : imgName.c_str(),
                (unsigned long)imgOff);
        fflush(g_logf);
        PIN_ReleaseLock(&g_events_lock);
    }
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
        "T%u [ALLOC]    "
        "Region_start=%p    "
        "Size=%zu   "
        "Type=%s    "
        "Caller=%s:%d   "
        "Caller_IMG=%s+0x%lx    "
        "Caller_PC=%p\n",
        (unsigned)tid,
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
        "T%u [FREE]     "
        "Region_start=%p    "
        "Region_Size=%zu    "
        "Type=%s    "
        "Free_ptr=%p    "
        "Caller=%s:%d   "
        "Caller_IMG=%s+0x%lx    "
        "Caller_PC=%p\n",
        (unsigned)tid,
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
        "T%u [FREE - UNKNOWN]   "
        "Free_ptr=%p    "
        "Caller=%s:%d   "
        "Caller_IMG=%s+0x%lx    "
        "Caller_PC=%p\n",
        (unsigned)tid,
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

static inline ThreadCtx* SafeCTX(THREADID tid, const char* who)
{
    ThreadCtx* tc = static_cast<ThreadCtx*>(PIN_GetThreadData(g_tls_key, tid));
    if (!tc || tc->magic != ThreadCtx::kMagic || tc->owner_tid != tid) {
        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            fprintf(g_logf, "[TLS-ANOMALY] %s tid=%u tc=%p magic_ok=%d owner=%d\n",
                    who, (unsigned)tid, (void*)tc,
                    (tc && tc->magic == ThreadCtx::kMagic),
                    tc ? (int)tc->owner_tid : -1);
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
        return nullptr;
    }
    return tc;
}

// Markaro to worker thread
static VOID MarkWorkerThread(THREADID tid)
{
    ThreadCtx* tc = SafeCTX(tid, "MarkWorkerThread");
    if (!tc) return;

    if (tc->role != ROLE_WORKER) {
        tc->role = ROLE_WORKER;

        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            fprintf(g_logf,
                    "[THREAD_ROLE] pin_tid=%u os_tid=%d role=WORKER\n",
                    (unsigned)tid, (int)tc->os_tid);
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
}

// ------------------------- Lookup helper -------------------------
static bool FindRegionWithOff(ADDRINT a, Region &out, size_t &off);

static bool FindStackRegionWithOff(THREADID tid, ADDRINT a, Region &out, size_t &off);


// Helper
static bool TryMarkHooked(RTN r)
{
    const ADDRINT a = RTN_Address(r);
    PIN_GetLock(&g_hook_lock, 0);
    bool fresh = g_hooked_rtn_addrs.insert(a).second;
    PIN_ReleaseLock(&g_hook_lock);
    return fresh; // true => first time we see this routine address
}
/*
static bool TryMarkHooked(RTN r)
{
    const ADDRINT a = RTN_Address(r);
    const std::string rawName = RTN_Name(r);

    PIN_GetLock(&g_hook_lock, 0);
    bool fresh = g_hooked_rtn_addrs.insert(a).second;
    PIN_ReleaseLock(&g_hook_lock);

    PIN_GetLock(&g_events_lock, 0);
    if (g_logf) {
        fprintf(g_logf,
                "[HOOK_CHECK] symbol=%s addr=%p result=%s\n",
                rawName.c_str(),
                (void*)a,
                fresh ? "HOOKED_FIRST_TIME" : "ALREADY_HOOKED");
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    return fresh;
}*/


// Helper gia ta counters ton symbols_29/3
/*static inline void BumpInstalledSymbol(const std::string& sym)
{
    PIN_GetLock(&g_stats_lock, 0);
    g_installed_symbols[sym]++;
    PIN_ReleaseLock(&g_stats_lock);
}*/

/*static inline void BumpCalledSymbol(const std::string& sym)
{
    PIN_GetLock(&g_stats_lock, 0);
    g_called_symbols[sym]++;
    PIN_ReleaseLock(&g_stats_lock);
}

static VOID PrintSymbolCountersSummary()
{
    if (!g_logf) return;

    PIN_GetLock(&g_stats_lock, 0);
    PIN_GetLock(&g_events_lock, 0);

    fprintf(g_logf, "\n========== SYMBOL HOOK SUMMARY ==========\n");

    // Πρώτα τύπωσε όλα τα installed symbols
    for (const auto& kv : g_installed_symbols) {
        const std::string& sym = kv.first;
        UINT64 installed = kv.second;

        UINT64 called = 0;
        auto it = g_called_symbols.find(sym);
        if (it != g_called_symbols.end()) {
            called = it->second;
        }

        fprintf(g_logf,
                "[SYMBOL] %-24s installed=%llu called=%llu\n",
                sym.c_str(),
                (unsigned long long)installed,
                (unsigned long long)called);
    }

    // Τύπωσε και όσα κλήθηκαν αλλά για κάποιο λόγο δεν υπήρχαν στο installed map
    for (const auto& kv : g_called_symbols) {
        const std::string& sym = kv.first;
        if (g_installed_symbols.find(sym) != g_installed_symbols.end()) continue;

        fprintf(g_logf,
                "[SYMBOL] %-24s installed=0 called=%llu\n",
                sym.c_str(),
                (unsigned long long)kv.second);
    }

    fprintf(g_logf, "=========================================\n");
    fflush(g_logf);

    PIN_ReleaseLock(&g_events_lock);
    PIN_ReleaseLock(&g_stats_lock);
}*/


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

static BOOL OnSigUsr2(THREADID tid, INT32 sig, CONTEXT* ctxt,
    BOOL hasHandler, const EXCEPTION_INFO* pExceptInfo, VOID* v)
{
(void)tid; (void)sig; (void)ctxt; (void)hasHandler; (void)pExceptInfo; (void)v;

g_trace_memops = !g_trace_memops;

PIN_GetLock(&g_events_lock, 0);
if (g_logf) {
fprintf(g_logf, "[CTRL] SIGUSR2 -> g_trace_memops=%d\n", (int)g_trace_memops);
fflush(g_logf);
}
if (tracef) {
//fprintf(tracef, "#CTRL g_trace_memops=%d\n", (int)g_trace_memops);
fflush(tracef);
}
PIN_ReleaseLock(&g_events_lock);

return FALSE; // do not deliver to application
}

static VOID RecordRead(THREADID tid, VOID* ip, VOID* ea, UINT32 bytes)
{
    if (!tracef) return;
    if (!g_trace_memops) return;

    const ADDRINT ipA = (ADDRINT)ip;
    const ADDRINT a   = (ADDRINT)ea;

    // Gia na tipono role
    ThreadCtx* tc = SafeCTX(tid, "RecordRead");
    if (!tc) return;

    /*Region snap;
    size_t off = 0;
    if (!FindRegionWithOff(a, snap, off)) return;*/

    Region snap;
    size_t off = 0;
    bool found = FindRegionWithOff(a, snap, off);
    //if (!found && !KnobTraceUntracked.Value()) return;
    /*if (!found) {
        found = FindStackRegionWithOff(tid, a, snap, off);
    }

    if (!found && !KnobTraceUntracked.Value()) return;*/
    // Μόνο αν το knob trace_stack είναι ενεργό, ψάξε και στο stack
    if (!found && KnobTraceStack.Value()) {
        found = FindStackRegionWithOff(tid, a, snap, off);
    }

    if (!found && !KnobTraceUntracked.Value()) return;


    if (bytes == 0) bytes = 1;

    // IMG + offset for the *instruction pointer*
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(ipA, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str(); // ή imgName.c_str() για full path
/*
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
            "T%u %p: load  base:%p full:%p tag=%s off=%zu size=%u ip_img=%s+0x%lx ALLOC_CALLER=%s:%d\n",
            (unsigned)tid, (void*)ipA,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes,
            imgC, (unsigned long)imgOff,
            snap.alloc_file.c_str(), (int)snap.alloc_line);
    PIN_ReleaseLock(&g_events_lock);*/

    PIN_GetLock(&g_events_lock, tid);

    if (!found) {
        /*fprintf(tracef,
            "T%u %p: load  full:%p UNTRACKED size=%u ip_img=%s+0x%lx\n",
            (unsigned)tid, (void*)ipA,
            (void*)a, bytes,
            imgC, (unsigned long)imgOff);*/
            fprintf(tracef,
                "T%u ROLE=%s OS_TID=%d %p: load  full:%p UNTRACKED size=%u ip_img=%s+0x%lx\n",
                (unsigned)tid,
                ThreadRoleStr(tc->role),
                (int)tc->os_tid,
                (void*)ipA,
                (void*)a, bytes,
                imgC, (unsigned long)imgOff);
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    if (off + (size_t)bytes > snap.size) {
        fprintf(tracef,
            "T%u %p: OOB_LOAD base:%p full:%p tag=%s off=%zu size=%u region_size=%zu ip_img=%s+0x%lx\n",
            (unsigned)tid, (void*)ipA,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes, snap.size,
            imgC, (unsigned long)imgOff);
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    /*fprintf(tracef,
        "T%u %p: load  base:%p full:%p tag=%s off=%zu size=%u ip_img=%s+0x%lx ALLOC_CALLER=%s:%d\n",
        (unsigned)tid, (void*)ipA,
        (void*)snap.start, (void*)a,
        snap.tag.c_str(), off, bytes,
        imgC, (unsigned long)imgOff,
        snap.alloc_file.c_str(), (int)snap.alloc_line);*/
        fprintf(tracef,
            "T%u ROLE=%s OS_TID=%d %p: load  base:%p full:%p tag=%s off=%zu size=%u ip_img=%s+0x%lx ALLOC_CALLER=%s:%d\n",
            (unsigned)tid,
            ThreadRoleStr(tc->role),
            (int)tc->os_tid,
            (void*)ipA,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes,
            imgC, (unsigned long)imgOff,
            snap.alloc_file.c_str(), (int)snap.alloc_line);

    PIN_ReleaseLock(&g_events_lock);
}

/*static VOID RecordWrite(THREADID tid, VOID* ip, VOID* ea, UINT32 bytes)
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
            "T%u %p: store base:%p full:%p tag=%s off=%zu size=%u ip_img=%s+0x%lx ALLOC_CALLER=%s:%d\n",
            (unsigned)tid, (void*)ipA,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes,
            imgC, (unsigned long)imgOff,
            snap.alloc_file.c_str(), (int)snap.alloc_line);
    PIN_ReleaseLock(&g_events_lock);
}*/
static VOID RecordWrite(THREADID tid, VOID* ip, VOID* ea, UINT32 bytes)
{
    if (!tracef) return;
    if (!g_trace_memops) return;

    const ADDRINT ipA = (ADDRINT)ip;
    const ADDRINT a   = (ADDRINT)ea;

    ThreadCtx* tc = SafeCTX(tid, "RecordWrite");
    if (!tc) return;

    Region snap;
    size_t off = 0;
    bool found = FindRegionWithOff(a, snap, off);
    //if (!found && !KnobTraceUntracked.Value()) return;
    /*if (!found) {
        found = FindStackRegionWithOff(tid, a, snap, off);
    }

    if (!found && !KnobTraceUntracked.Value()) return;*/
    // Μόνο αν το knob trace_stack είναι ενεργό, ψάξε και στο stack
    if (!found && KnobTraceStack.Value()) {
        found = FindStackRegionWithOff(tid, a, snap, off);
    }

    if (!found && !KnobTraceUntracked.Value()) return;

    if (bytes == 0) bytes = 1;

    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(ipA, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    PIN_GetLock(&g_events_lock, tid);

    if (!found) {
        /*fprintf(tracef,
            "T%u %p: store full:%p UNTRACKED size=%u ip_img=%s+0x%lx\n",
            (unsigned)tid, (void*)ipA,
            (void*)a, bytes,
            imgC, (unsigned long)imgOff);*/
            fprintf(tracef,
                "T%u ROLE=%s OS_TID=%d %p: store full:%p UNTRACKED size=%u ip_img=%s+0x%lx\n",
                (unsigned)tid,
                ThreadRoleStr(tc->role),
                (int)tc->os_tid,
                (void*)ipA,
                (void*)a, bytes,
                imgC, (unsigned long)imgOff);
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    if (off + (size_t)bytes > snap.size) {
        fprintf(tracef,
            "T%u %p: OOB_STORE base:%p full:%p tag=%s off=%zu size=%u region_size=%zu ip_img=%s+0x%lx\n",
            (unsigned)tid, (void*)ipA,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes, snap.size,
            imgC, (unsigned long)imgOff);
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    /*fprintf(tracef,
        "T%u %p: store base:%p full:%p tag=%s off=%zu size=%u ip_img=%s+0x%lx ALLOC_CALLER=%s:%d\n",
        (unsigned)tid, (void*)ipA,
        (void*)snap.start, (void*)a,
        snap.tag.c_str(), off, bytes,
        imgC, (unsigned long)imgOff,
        snap.alloc_file.c_str(), (int)snap.alloc_line);*/
        fprintf(tracef,
            "T%u ROLE=%s OS_TID=%d %p: store base:%p full:%p tag=%s off=%zu size=%u ip_img=%s+0x%lx ALLOC_CALLER=%s:%d\n",
            (unsigned)tid,
            ThreadRoleStr(tc->role),
            (int)tc->os_tid,
            (void*)ipA,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off, bytes,
            imgC, (unsigned long)imgOff,
            snap.alloc_file.c_str(), (int)snap.alloc_line);

    PIN_ReleaseLock(&g_events_lock);
}

/*static BOOL ShouldInstrumentIns(INS ins) {

    // Βρίσκουμε σε ποιο image ανήκει η εντολή (exe ή shared lib)
    IMG img = IMG_FindByAddress(INS_Address(ins));
    if (!IMG_Valid(img)) return FALSE;

    // Κάνε trace ΜΟΝΟ το main executable (π.χ. ds_demo, memcached)
    return IMG_IsMainExecutable(img);
}*/

static BOOL ShouldInstrumentIns(INS ins) {

    // Βρίσκουμε σε ποιο image ανήκει η εντολή (exe ή shared lib)
    IMG img = IMG_FindByAddress(INS_Address(ins));
    if (!IMG_Valid(img)) return FALSE;

    // Αν το knob είναι ON, κράτα μόνο το main executable
    if (KnobMainExeOnly.Value())
        return IMG_IsMainExecutable(img);

    // Αλλιώς κράτα όλα τα images
    return TRUE;
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

    if (g_logf) {
        fprintf(g_logf,
            "[ANOMALY] alloc_overlap new_start=%p new_size=%zu new_tag=%s "
            "overlap_start=%p overlap_size=%zu overlap_tag=%s @%s:%d (%s) pc=%p\n",
            (void*)r.start, r.size, r.tag.c_str(),
            (void*)ov.start, ov.size, ov.tag.c_str(),
            file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        fflush(g_logf);
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

    if (g_logf) {
        fprintf(g_logf, "[HOOK ALLOC] p=%p size=%zu tag=%s @%s:%d (%s) pc=%p\n",
                ptr, size, tag, file ? file : "?", line, func ? func : "?", (void*)caller_ip);
        fflush(g_logf);
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

    if (g_logf) {
        fprintf(g_logf, "[HOOK FREE ] p=%p tag=%s @%s:%d (%s)%s pc=%p\n",
                ptr, tag,
                file ? file : "?", line, func ? func : "?",
                known ? "" : " (UNKNOWN)",(void*)caller_ip) ;
        fflush(g_logf);
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
                if (g_logf) {
                    fprintf(g_logf, "[HOOK] __memtrace_alloc_site in %s\n",
                            IMG_Name(img).c_str());
                    fflush(g_logf);
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
                if (g_logf) {
                    fprintf(g_logf, "[HOOK] __memtrace_free_site in %s\n",
                            IMG_Name(img).c_str());
                    fflush(g_logf);
                }
                PIN_ReleaseLock(&g_events_lock);
            }
        }
    }
}
// ---- forward declarations for After* used by TLS wrappers ----
static VOID AfterMalloc(ADDRINT ret, size_t sz, ADDRINT caller_ip);
static VOID AfterCalloc(ADDRINT ret, size_t n, size_t sz, ADDRINT caller_ip);
static VOID AfterRealloc(ADDRINT ret, ADDRINT oldp, size_t sz, ADDRINT caller_ip);
static VOID AfterReallocarray(ADDRINT ret, ADDRINT oldp, size_t nmemb, size_t elemsz, ADDRINT caller_ip);

static VOID* Realloc_Replacement(CONTEXT* ctxt, THREADID tid,
    AFUNPTR orig,
    ADDRINT oldp, size_t sz, ADDRINT caller_ip)
{
    //BumpCalledSymbol("realloc_replacement");

    VOID* ret = nullptr;
    ThreadCtx* tc = SafeCTX(tid, "Realloc_Replacement");
    if (tc) tc->inRealloc++;

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] Realloc_Replacement BEFORE tid=%u oldp=%p sz=%zu caller=%p\n",
                (unsigned)tid,
                (void*)oldp,
                sz,
                (void*)caller_ip);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    PIN_CallApplicationFunction(
        ctxt, tid, CALLINGSTD_DEFAULT,
        orig, nullptr,
        PIN_PARG(void*), &ret,
        PIN_PARG(void*), (void*)oldp,
        PIN_PARG(size_t), sz,
        PIN_PARG_END()
    );

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] Realloc_Replacement AFTER  tid=%u ret=%p oldp=%p sz=%zu caller=%p\n",
                (unsigned)tid,
                ret,
                (void*)oldp,
                sz,
                (void*)caller_ip);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    AfterRealloc((ADDRINT)ret, oldp, sz, caller_ip);
    if (tc) tc->inRealloc--;

    return ret;
}

//last change
/*
enum class MunmapActionKind {
    ERASE_FULL,   // region removed completely
    TRIM_HEAD,    // remove beginning of region -> start moves forward
    TRIM_TAIL,    // remove end of region -> size shrinks
    SPLIT         // remove middle -> split into left + right
};

struct MunmapAction {
    MunmapActionKind kind;
    Region before;
    Region after_left;   // for TRIM_TAIL or SPLIT (left part)
    Region after_right;  // for TRIM_HEAD or SPLIT (right part)
    ADDRINT unmap_start;
    size_t  unmap_len;
};

// assumes: caller checks rc==0 and addr!=0 and len!=0 and no overflow
static void MunmapRangeUpdateMap(THREADID tid, ADDRINT addr, size_t len,
                                 std::vector<MunmapAction>& actions_out)
{
    actions_out.clear();

    const ADDRINT start = addr;
    const ADDRINT end   = addr + (ADDRINT)len; // caller ensured no overflow

    PIN_GetLock(&g_regions_lock, tid);

    // start iteration near the first possible overlapping region
    auto it = g_regions.lower_bound(start);
    if (it != g_regions.begin()) {
        auto prev = it; --prev;
        // if prev overlaps start, we must consider it
        const ADDRINT prev_end = prev->second.start + (ADDRINT)prev->second.size;
        if (prev_end > start) it = prev;
    }

    while (it != g_regions.end()) {
        Region r = it->second;
        const ADDRINT r_start = r.start;
        const ADDRINT r_end   = r.start + (ADDRINT)r.size;

        // if region starts beyond unmap end -> stop
        if (r_start >= end) break;

        // if region ends before start -> next
        if (r_end <= start) { ++it; continue; }

        // Now we have overlap between [r_start,r_end) and [start,end)
        const bool cover_full = (start <= r_start) && (end >= r_end);
        const bool cut_head   = (start <= r_start) && (end <  r_end); // cut from beginning of region
        const bool cut_tail   = (start >  r_start) && (end >= r_end); // cut from end of region
        const bool cut_mid    = (start >  r_start) && (end <  r_end); // cut middle -> split

        if (cover_full) {
            MunmapAction a;
            a.kind = MunmapActionKind::ERASE_FULL;
            a.before = r;
            a.unmap_start = start;
            a.unmap_len = len;
            actions_out.push_back(a);

            it = g_regions.erase(it);
            continue;
        }

        if (cut_head) {
            // remove [r_start, end) -> keep [end, r_end)
            const ADDRINT new_start = end;
            const size_t  new_size  = (size_t)(r_end - end);

            Region newr = r;
            newr.start = new_start;
            newr.size  = new_size;

            MunmapAction a;
            a.kind = MunmapActionKind::TRIM_HEAD;
            a.before = r;
            a.after_right = newr;
            a.unmap_start = start;
            a.unmap_len = len;
            actions_out.push_back(a);

            // erase old key and insert new key
            it = g_regions.erase(it);
            g_regions[newr.start] = newr;

            // continue from next possible overlap (newr starts at end, so no further overlap with [start,end))
            it = g_regions.lower_bound(end);
            continue;
        }

        if (cut_tail) {
            // remove [start, r_end) -> keep [r_start, start)
            const size_t new_size = (size_t)(start - r_start);

            MunmapAction a;
            a.kind = MunmapActionKind::TRIM_TAIL;
            a.before = r;

            Region left = r;
            left.size = new_size;
            a.after_left = left;

            a.unmap_start = start;
            a.unmap_len = len;
            actions_out.push_back(a);

            it->second.size = new_size;
            ++it;
            continue;
        }

        if (cut_mid) {
            // keep left: [r_start, start)
            // keep right:[end, r_end)
            const size_t left_size  = (size_t)(start - r_start);
            const size_t right_size = (size_t)(r_end - end);

            Region left = r;
            left.size = left_size;

            Region right = r;
            right.start = end;
            right.size  = right_size;

            MunmapAction a;
            a.kind = MunmapActionKind::SPLIT;
            a.before = r;
            a.after_left = left;
            a.after_right = right;
            a.unmap_start = start;
            a.unmap_len = len;
            actions_out.push_back(a);

            // update current to left, insert right
            it->second = left;
            g_regions[right.start] = right;

            // right starts at end, so no overlap with [start,end) anymore
            it = g_regions.lower_bound(end);
            continue;
        }

        // should not reach
        ++it;
    }

    PIN_ReleaseLock(&g_regions_lock);
}

// helper: safe overflow check for [addr, addr+len)
static inline bool RangeEndNoOverflow(ADDRINT addr, size_t len, ADDRINT& out_end)
{
    if (len == 0) return false;
    const ADDRINT end = addr + (ADDRINT)len;
    if (end < addr) return false; // overflow
    out_end = end;
    return true;
}*/
//mexri edw

static VOID AfterMmap(ADDRINT ret, size_t length, ADDRINT caller_ip);
static VOID AfterMunmap(INT32 rc, ADDRINT addr, size_t length, ADDRINT caller_ip);
static VOID AfterMremap(ADDRINT ret, ADDRINT oldp, size_t oldsz, size_t newsz, ADDRINT caller_ip);


// ----------------- Optional glibc malloc/free hooks --------------
// otan energopoihthei to knob use_libc_hooks, kanoume hook ta malloc/calloc/realloc/free

static VOID BeforeMallocTLS(THREADID tid, size_t sz, ADDRINT caller_ip) {
    //if (tc->hasPendingMalloc) { /* optional log anomaly */ }
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "BeforeMallocTLS");
    if (!tc) return;
    tc->hasPendingMalloc = true;
    tc->pendingMallocSize = sz;
    tc->pendingMallocCallerIp = caller_ip;
}


//debug aftermalloctlc
static VOID AfterMallocTLS(THREADID tid, ADDRINT ret) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "AfterMallocTLS");
    if (!tc) return;

    if (!tc->hasPendingMalloc) return;

    AfterMalloc(ret, tc->pendingMallocSize, tc->pendingMallocCallerIp);

    tc->hasPendingMalloc = false;
    tc->pendingMallocSize = 0;
    tc->pendingMallocCallerIp = 0;
}


static VOID BeforeCallocTLS(THREADID tid, size_t n, size_t sz, ADDRINT caller_ip) {
    ThreadCtx* tc = SafeCTX(tid, "BeforeCallocTLS");
    if (!tc) return;

    UINT64 seq = 0;
    if (!ThreadCtx::CallocPush(tc, n, sz, caller_ip, seq)) {
        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            fprintf(g_logf, "[ANOMALY] calloc stack overflow T%u n=%zu sz=%zu ip=%p top=%d\n",
                    (unsigned)tid, n, sz, (void*)caller_ip, tc->pendingCallocTop);
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    // (προαιρετικό) debug log
    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf, "[DBG] calloc PUSH T%u seq=%llu n=%zu sz=%zu top=%d ip=%p\n",
                (unsigned)tid, (unsigned long long)seq, n, sz, tc->pendingCallocTop, (void*)caller_ip);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);
}

static VOID AfterCallocTLS(THREADID tid, ADDRINT ret) {
    ThreadCtx* tc = SafeCTX(tid, "AfterCallocTLS");
    if (!tc) return;

    ThreadCtx::PendingCalloc p;
    if (!ThreadCtx::CallocPop(tc, p)) {
        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            fprintf(g_logf, "[ANOMALY] calloc POP EMPTY T%u ret=%p\n",
                    (unsigned)tid, (void*)ret);
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    // (προαιρετικό) debug log
    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf, "[DBG] calloc POP  T%u seq=%llu n=%zu sz=%zu top=%d ret=%p\n",
                (unsigned)tid, (unsigned long long)p.seq, p.n, p.sz, tc->pendingCallocTop, (void*)ret);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    AfterCalloc(ret, p.n, p.sz, p.callerIp);
}

/*static VOID BeforeReallocTLS(THREADID tid, ADDRINT oldp, size_t sz, ADDRINT caller_ip) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "BeforeReallocTLS");
    if (!tc) return;
    tc->hasPendingRealloc = true;
    tc->pendingReallocOldp = oldp;
    tc->pendingReallocSz = sz;
    tc->pendingReallocCallerIp = caller_ip;
}*/
static VOID BeforeReallocTLS(THREADID tid, ADDRINT oldp, size_t sz, ADDRINT caller_ip) {
    //BumpCalledSymbol("realloc_family");

    ThreadCtx* tc = SafeCTX(tid, "BeforeReallocTLS");
    if (!tc) return;

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] BeforeReallocTLS tid=%u oldp=%p sz=%zu caller=%p\n",
                (unsigned)tid,
                (void*)oldp,
                sz,
                (void*)caller_ip);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    tc->hasPendingRealloc = true;
    tc->pendingReallocOldp = oldp;
    tc->pendingReallocSz = sz;
    tc->pendingReallocCallerIp = caller_ip;
}

/*static VOID AfterReallocTLS(THREADID tid, ADDRINT ret) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "AfterReallocTLS");
    if (!tc || !tc->hasPendingRealloc) return;
    AfterRealloc(ret, tc->pendingReallocOldp, tc->pendingReallocSz, tc->pendingReallocCallerIp);
    tc->hasPendingRealloc = false;
    tc->pendingReallocOldp = 0;
    tc->pendingReallocSz = 0;
    tc->pendingReallocCallerIp = 0;
}*/
static VOID AfterReallocTLS(THREADID tid, ADDRINT ret) {
    ThreadCtx* tc = SafeCTX(tid, "AfterReallocTLS");
    if (!tc || !tc->hasPendingRealloc) return;

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] AfterReallocTLS tid=%u ret=%p oldp=%p sz=%zu caller=%p\n",
                (unsigned)tid,
                (void*)ret,
                (void*)tc->pendingReallocOldp,
                tc->pendingReallocSz,
                (void*)tc->pendingReallocCallerIp);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    AfterRealloc(ret, tc->pendingReallocOldp, tc->pendingReallocSz, tc->pendingReallocCallerIp);

    tc->hasPendingRealloc = false;
    tc->pendingReallocOldp = 0;
    tc->pendingReallocSz = 0;
    tc->pendingReallocCallerIp = 0;
}

static VOID BeforeReallocarrayTLS(THREADID tid, ADDRINT oldp, size_t nmemb, size_t elemsz, ADDRINT caller_ip) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "BeforeReallocarrayTLS");
    if (!tc) return;
    tc->hasPendingReallocarray = true;
    tc->pendingReallocarrayOldp = oldp;
    tc->pendingReallocarrayNmemb = nmemb;
    tc->pendingReallocarrayElemsz = elemsz;
    tc->pendingReallocarrayCallerIp = caller_ip;
}

static VOID AfterReallocarrayTLS(THREADID tid, ADDRINT ret) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "AfterReallocarrayTLS");
    if (!tc || !tc->hasPendingReallocarray) return;
    AfterReallocarray(ret,
        tc->pendingReallocarrayOldp,
        tc->pendingReallocarrayNmemb,
        tc->pendingReallocarrayElemsz,
        tc->pendingReallocarrayCallerIp);
    tc->hasPendingReallocarray = false;
    tc->pendingReallocarrayOldp = 0;
    tc->pendingReallocarrayNmemb = tc->pendingReallocarrayElemsz = 0;
    tc->pendingReallocarrayCallerIp = 0;
}

static VOID BeforeMmapTLS(THREADID tid, size_t length, ADDRINT caller_ip) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "BeforeMmapTLS");
    if (!tc) return;
    tc->hasPendingMmap = true;
    tc->pendingMmapLen = length;
    tc->pendingMmapCallerIp = caller_ip;
}
static VOID AfterMmapTLS(THREADID tid, ADDRINT ret) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "AfterMmapTLS");
    if (!tc || !tc->hasPendingMmap) return;
    AfterMmap(ret, tc->pendingMmapLen, tc->pendingMmapCallerIp);
    tc->hasPendingMmap = false;
    tc->pendingMmapLen = 0;
    tc->pendingMmapCallerIp = 0;
}

static VOID BeforeMunmapTLS(THREADID tid, ADDRINT addr, size_t length, ADDRINT caller_ip) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "BeforeMunmapTLS");
    if (!tc) return;
    tc->hasPendingMunmap = true;
    tc->pendingMunmapAddr = addr;
    tc->pendingMunmapLen = length;
    tc->pendingMunmapCallerIp = caller_ip;
}
static VOID AfterMunmapTLS(THREADID tid, INT32 rc) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "AfterMunmapTLS");
    if (!tc || !tc->hasPendingMunmap) return;
    AfterMunmap(rc, tc->pendingMunmapAddr, tc->pendingMunmapLen, tc->pendingMunmapCallerIp);
    tc->hasPendingMunmap = false;
    tc->pendingMunmapAddr = 0;
    tc->pendingMunmapLen = 0;
    tc->pendingMunmapCallerIp = 0;
}

static VOID BeforeMremapTLS(THREADID tid, ADDRINT oldp, size_t oldsz, size_t newsz, ADDRINT caller_ip) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "BeforeMremapTLS");
    if (!tc) return;
    tc->hasPendingMremap = true;
    tc->pendingMremapOldp = oldp;
    tc->pendingMremapOldsz = oldsz;
    tc->pendingMremapNewsz = newsz;
    tc->pendingMremapCallerIp = caller_ip;
}
static VOID AfterMremapTLS(THREADID tid, ADDRINT ret) {
    //ThreadCtx* tc = CTX(tid);
    ThreadCtx* tc = SafeCTX(tid, "AfterMremapTLS");
    if (!tc || !tc->hasPendingMremap) return;
    AfterMremap(ret, tc->pendingMremapOldp, tc->pendingMremapOldsz, tc->pendingMremapNewsz, tc->pendingMremapCallerIp);
    tc->hasPendingMremap = false;
    tc->pendingMremapOldp = 0;
    tc->pendingMremapOldsz = tc->pendingMremapNewsz = 0;
    tc->pendingMremapCallerIp = 0;
}

static VOID AfterMalloc(ADDRINT ret, size_t sz, ADDRINT caller_ip) {
    if (!ret ) return;      //|| sz == 0
    THREADID tid = PIN_ThreadId();
    ThreadCtx* tc = SafeCTX(tid, "AfterMalloc");

    // Αν το malloc γίνεται εσωτερικά μέσα από realloc replacement,
    // μην το γράψεις σαν ξεχωριστό heap:malloc event
    if (tc && tc->inRealloc > 0) {
        return;
    }
    //real size
    //size_t bytes = NormalizeAllocSize((void*)ret, sz);
    size_t bytes = sz;   // requested only
    //debug msg
    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        std::string imgName; ADDRINT imgOff = 0;
        GetImgFromIp(caller_ip, imgName, imgOff);
                fprintf(g_logf, "[MALLOC HIT] ret=%p req=%zu caller_pc=%p img=%s+0x%lx\n",
                    (void*)ret, sz, (void*)caller_ip,
                    imgName.c_str(), (unsigned long)imgOff);
        fflush(g_logf);
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
    Region r;
    r.start = ret;
    r.size = bytes;
    r.tag = "heap:malloc";     //r.size =sz;  //θα το αλλάξουμε σε πραγματικό size με βάση το malloc_usable_size
    r.alloc_file = srcFileC;    //for caller on load/store
    r.alloc_line = srcLine;     //for caller on load/store
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

    THREADID tid = PIN_ThreadId();

    if (!ret) {
        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            fprintf(g_logf,
                    "[DBG] AfterCalloc NULLRET tid=%u n=%zu sz=%zu caller=%p\n",
                    (unsigned)tid,
                    n, sz,
                    (void*)caller_ip);
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] AfterCalloc ENTER tid=%u ret=%p n=%zu sz=%zu caller=%p\n",
                (unsigned)tid,
                (void*)ret,
                n, sz,
                (void*)caller_ip);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    size_t bytes = 0;
    if (n != 0 && sz != 0) {
        if (n > (std::numeric_limits<size_t>::max() / sz)) {
            PIN_GetLock(&g_events_lock, tid);
            if (g_logf) {
                fprintf(g_logf,
                        "[DBG] AfterCalloc OVERFLOW tid=%u n=%zu sz=%zu caller=%p\n",
                        (unsigned)tid,
                        n, sz,
                        (void*)caller_ip);
                fflush(g_logf);
            }
            PIN_ReleaseLock(&g_events_lock);
            return; // overflow -> μην κάνεις update
        }
        bytes = n * sz;
    } else {
        bytes = 0; // calloc(0, x) ή calloc(x,0) -> bytes 0 αλλά ptr μπορεί να είναι non-null
    }

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] AfterCalloc BYTES tid=%u bytes=%zu n=%zu sz=%zu ret=%p\n",
                (unsigned)tid,
                bytes,
                n, sz,
                (void*)ret);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    // caller source location
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // image name + offset
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] AfterCalloc INSERT tid=%u ret=%p bytes=%zu caller=%p src=%s:%d img=%s+0x%lx\n",
                (unsigned)tid,
                (void*)ret,
                bytes,
                (void*)caller_ip,
                srcFileC,
                (int)srcLine,
                imgC,
                (unsigned long)imgOff);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    PIN_GetLock(&g_regions_lock, tid);
    Region r;
    r.start = ret;
    r.size = bytes;
    r.tag = "heap:calloc";
    r.alloc_file = srcFileC;
    r.alloc_line = srcLine;
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);

    // trace
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

    // eventsf
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

/*static VOID* Calloc_Replacement(CONTEXT* ctxt, THREADID tid,
    AFUNPTR orig,
    size_t n, size_t sz, ADDRINT caller_ip)
{
VOID* ret = nullptr;
ThreadCtx* tc = SafeCTX(tid, "Calloc_Replacement");
if (tc) tc->inCalloc++;

PIN_CallApplicationFunction(
ctxt, tid, CALLINGSTD_DEFAULT,
orig, nullptr,
PIN_PARG(void*), &ret,
PIN_PARG(size_t), n,
PIN_PARG(size_t), sz,
PIN_PARG_END()
);

AfterCalloc((ADDRINT)ret, n, sz, caller_ip);

if (tc) tc->inCalloc--;
return ret;
}*/

// debug msg for Calloc_Replacement
static VOID* Calloc_Replacement(CONTEXT* ctxt, THREADID tid,
    AFUNPTR orig,
    size_t n, size_t sz, ADDRINT caller_ip)
{
    VOID* ret = nullptr;
    ThreadCtx* tc = SafeCTX(tid, "Calloc_Replacement");
    if (tc) tc->inCalloc++;

    //debug msg
    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] Calloc_Replacement ENTER tid=%u n=%zu sz=%zu caller=%p orig=%p\n",
                (unsigned)tid,
                n, sz,
                (void*)caller_ip,
                (void*)orig);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    PIN_CallApplicationFunction(
        ctxt, tid, CALLINGSTD_DEFAULT,
        orig, nullptr,
        PIN_PARG(void*), &ret,
        PIN_PARG(size_t), n,
        PIN_PARG(size_t), sz,
        PIN_PARG_END()
    );

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] Calloc_Replacement AFTER tid=%u ret=%p n=%zu sz=%zu caller=%p\n",
                (unsigned)tid,
                ret,
                n, sz,
                (void*)caller_ip);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    AfterCalloc((ADDRINT)ret, n, sz, caller_ip);

    if (tc) tc->inCalloc--;
    return ret;
}

static VOID AfterRealloc(ADDRINT ret, ADDRINT oldp, size_t sz, ADDRINT caller_ip) {
    THREADID tid = PIN_ThreadId();
    // debug msg
    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] AfterRealloc ENTER tid=%u ret=%p oldp=%p sz=%zu caller=%p\n",
                (unsigned)tid,
                (void*)ret,
                (void*)oldp,
                sz,
                (void*)caller_ip);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

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
        //size_t bytes = NormalizeAllocSize((void*)ret, sz);
        size_t bytes = sz;   // requested only
        PIN_GetLock(&g_regions_lock, tid);
        Region r; r.start = ret; r.size = bytes; r.tag = "heap:realloc";
        r.alloc_file = srcFileC;
        r.alloc_line = srcLine;
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

static bool FindStackRegionWithOff(THREADID tid, ADDRINT a, Region &out, size_t &off)
{
    bool found = false;

    PIN_GetLock(&g_stack_lock, tid);

    auto it = g_stack_regions.find(tid);
    if (it != g_stack_regions.end()) {
        const Region &r = it->second;
        ADDRINT end = r.start + (ADDRINT)r.size;

        if (end >= r.start && a >= r.start && a < end) {
            out = r;
            off = (size_t)(a - r.start);
            found = true;
        }
    }

    PIN_ReleaseLock(&g_stack_lock);
    return found;
}

static VOID BeforeFree(ADDRINT p, ADDRINT caller_ip) {
    // (1) Ignore free(NULL) completely
    if (p == 0) return;

    THREADID tid = PIN_ThreadId();
    // ---- Image name + offset ----
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);   // client-lock

    // ---- Source location (κρατάμε αυτό που είχες) ----
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    
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

/*static VOID AfterMmap(ADDRINT ret, size_t length, ADDRINT caller_ip)
{
    //Debug msg
    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] AfterMmap ENTER tid=%u ret=%p length=%zu caller=%p\n",
                (unsigned)tid,
                (void*)ret,
                length,
                (void*)caller_ip);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

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
    r.alloc_file = srcFileC;    //for load/store caller
    r.alloc_line = srcLine;
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
}*/
static VOID AfterMmap(ADDRINT ret, size_t length, ADDRINT caller_ip)
{
    THREADID tid = PIN_ThreadId();

    if (!ret || ret == (ADDRINT)-1 || length == 0) {
        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            fprintf(g_logf,
                    "[DBG] AfterMmap SKIP tid=%u ret=%p length=%zu caller=%p\n",
                    (unsigned)tid,
                    (void*)ret,
                    length,
                    (void*)caller_ip);
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] AfterMmap ENTER tid=%u ret=%p length=%zu caller=%p\n",
                (unsigned)tid,
                (void*)ret,
                length,
                (void*)caller_ip);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    // caller source location
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // image name + offset
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[DBG] AfterMmap INSERT tid=%u ret=%p length=%zu caller=%p src=%s:%d img=%s+0x%lx\n",
                (unsigned)tid,
                (void*)ret,
                length,
                (void*)caller_ip,
                srcFileC,
                (int)srcLine,
                imgC,
                (unsigned long)imgOff);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

    PIN_GetLock(&g_regions_lock, tid);
    Region r; r.start = ret; r.size = length; r.tag = "mmap";
    r.alloc_file = srcFileC;
    r.alloc_line = srcLine;
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
                   caller_ip);
    }
    PIN_ReleaseLock(&g_events_lock);
}

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

//last change 
/*
static VOID AfterMunmap(INT32 rc, ADDRINT addr, size_t length, ADDRINT caller_ip)
{
    if (rc != 0) return;
    if (!addr || length == 0) return;

    ADDRINT end = 0;
    if (!RangeEndNoOverflow(addr, length, end)) return;

    THREADID tid = PIN_ThreadId();

    // caller source location (OUTSIDE locks)
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    // image name + offset (OUTSIDE locks)
    std::string imgName;
    ADDRINT imgOff = 0;
    GetImgFromIp(caller_ip, imgName, imgOff);
    const char* imgC = imgName.empty() ? "?" : imgName.c_str();

    // NEW: range-based update
    std::vector<MunmapAction> acts;
    MunmapRangeUpdateMap(tid, addr, length, acts);

    // Now emit logs atomically
    PIN_GetLock(&g_events_lock, tid);

    if (acts.empty()) {
        // nothing overlapped -> unknown munmap in our tracking
        if (eventsf) {
            fprintf(eventsf,
                    "free  start=%p tag=UNKNOWN_MUNMAP range=[%p,%p) len=%zu site=%s:%d img=%s+0x%lx pc=%p\n",
                    (void*)addr, (void*)addr, (void*)end, length,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
            fflush(eventsf);
        }
        if (tracef) {
            fprintf(tracef,
                    "T%u ANOMALY munmap_unknown addr=%p len=%zu range=[%p,%p) site=%s:%d img=%s+0x%lx pc=%p\n",
                    (unsigned)tid, (void*)addr, length, (void*)addr, (void*)end,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
            fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    // for each affected region: print what happened
    for (const auto& a : acts) {
        switch (a.kind) {
            case MunmapActionKind::ERASE_FULL: {
                // treat as "free" of the whole region
                if (eventsf) {
                    fprintf(eventsf,
                            "free  start=%p size=%zu tag=%s munmap_range=[%p,%p) site=%s:%d img=%s+0x%lx pc=%p\n",
                            (void*)a.before.start, a.before.size, a.before.tag.c_str(),
                            (void*)addr, (void*)end,
                            srcFileC, (int)srcLine,
                            imgC, (unsigned long)imgOff,
                            (void*)caller_ip);
                    fflush(eventsf);
                }
                if (tracef) {
                    PrintFreeKnown(tid,
                        (ADDRINT)a.before.start,
                        a.before.size,
                        a.before.tag.c_str(),
                        (ADDRINT)addr, // Free_ptr = munmap addr (range-based)
                        srcFileC,
                        (int)srcLine,
                        imgC,
                        (unsigned long)imgOff,
                        caller_ip
                    );
                }
                break;
            }

            case MunmapActionKind::TRIM_HEAD: {
                if (eventsf) {
                    fprintf(eventsf,
                            "ANOMALY munmap_trim_head old=[%p,%p) new=[%p,%p) tag=%s munmap=[%p,%p) site=%s:%d img=%s+0x%lx pc=%p\n",
                            (void*)a.before.start, (void*)(a.before.start + a.before.size),
                            (void*)a.after_right.start, (void*)(a.after_right.start + a.after_right.size),
                            a.before.tag.c_str(),
                            (void*)addr, (void*)end,
                            srcFileC, (int)srcLine,
                            imgC, (unsigned long)imgOff,
                            (void*)caller_ip);
                    fflush(eventsf);
                }
                if (tracef) {
                    fprintf(tracef,
                            "T%u ANOMALY munmap_trim_head old=[%p,%p) new=[%p,%p) tag=%s munmap=[%p,%p) site=%s:%d img=%s+0x%lx pc=%p\n",
                            (unsigned)tid,
                            (void*)a.before.start, (void*)(a.before.start + a.before.size),
                            (void*)a.after_right.start, (void*)(a.after_right.start + a.after_right.size),
                            a.before.tag.c_str(),
                            (void*)addr, (void*)end,
                            srcFileC, (int)srcLine,
                            imgC, (unsigned long)imgOff,
                            (void*)caller_ip);
                    fflush(tracef);
                }
                break;
            }

            case MunmapActionKind::TRIM_TAIL: {
                if (eventsf) {
                    fprintf(eventsf,
                            "ANOMALY munmap_trim_tail old=[%p,%p) new=[%p,%p) tag=%s munmap=[%p,%p) site=%s:%d img=%s+0x%lx pc=%p\n",
                            (void*)a.before.start, (void*)(a.before.start + a.before.size),
                            (void*)a.after_left.start, (void*)(a.after_left.start + a.after_left.size),
                            a.before.tag.c_str(),
                            (void*)addr, (void*)end,
                            srcFileC, (int)srcLine,
                            imgC, (unsigned long)imgOff,
                            (void*)caller_ip);
                    fflush(eventsf);
                }
                if (tracef) {
                    fprintf(tracef,
                            "T%u ANOMALY munmap_trim_tail old=[%p,%p) new=[%p,%p) tag=%s munmap=[%p,%p) site=%s:%d img=%s+0x%lx pc=%p\n",
                            (unsigned)tid,
                            (void*)a.before.start, (void*)(a.before.start + a.before.size),
                            (void*)a.after_left.start, (void*)(a.after_left.start + a.after_left.size),
                            a.before.tag.c_str(),
                            (void*)addr, (void*)end,
                            srcFileC, (int)srcLine,
                            imgC, (unsigned long)imgOff,
                            (void*)caller_ip);
                    fflush(tracef);
                }
                break;
            }

            case MunmapActionKind::SPLIT: {
                if (eventsf) {
                    fprintf(eventsf,
                            "ANOMALY munmap_split old=[%p,%p) left=[%p,%p) right=[%p,%p) tag=%s munmap=[%p,%p) site=%s:%d img=%s+0x%lx pc=%p\n",
                            (void*)a.before.start, (void*)(a.before.start + a.before.size),
                            (void*)a.after_left.start, (void*)(a.after_left.start + a.after_left.size),
                            (void*)a.after_right.start, (void*)(a.after_right.start + a.after_right.size),
                            a.before.tag.c_str(),
                            (void*)addr, (void*)end,
                            srcFileC, (int)srcLine,
                            imgC, (unsigned long)imgOff,
                            (void*)caller_ip);
                    fflush(eventsf);
                }
                if (tracef) {
                    fprintf(tracef,
                            "T%u ANOMALY munmap_split old=[%p,%p) left=[%p,%p) right=[%p,%p) tag=%s munmap=[%p,%p) site=%s:%d img=%s+0x%lx pc=%p\n",
                            (unsigned)tid,
                            (void*)a.before.start, (void*)(a.before.start + a.before.size),
                            (void*)a.after_left.start, (void*)(a.after_left.start + a.after_left.size),
                            (void*)a.after_right.start, (void*)(a.after_right.start + a.after_right.size),
                            a.before.tag.c_str(),
                            (void*)addr, (void*)end,
                            srcFileC, (int)srcLine,
                            imgC, (unsigned long)imgOff,
                            (void*)caller_ip);
                    fflush(tracef);
                }
                break;
            }
        }
    }

    PIN_ReleaseLock(&g_events_lock);
}*/
//mexri edw

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
        r.alloc_file = srcFileC;
        r.alloc_line = srcLine;
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

// hookaro to worker_libevent pu einai i function sto memcached pou dimiourgei ta workers sto thread.c arxeio tou memcached 
static VOID HookMemcachedThreadRoles(IMG img)
{
    // Μόνο στο main executable (memcached)
    if (!IMG_IsMainExecutable(img)) return;

    RTN r = RTN_FindByName(img, "worker_libevent");
    if (!RTN_Valid(r)) {
        PIN_GetLock(&g_events_lock, 0);
        if (g_logf) {
            fprintf(g_logf, "[WARN] worker_libevent not found in %s\n",
                    IMG_Name(img).c_str());
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
        return;
    }

    if (!TryMarkHooked(r)) return;

    RTN_Open(r);
    RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(MarkWorkerThread),
        IARG_THREAD_ID,
        IARG_END);
    RTN_Close(r);

    PIN_GetLock(&g_events_lock, 0);
    if (g_logf) {
        fprintf(g_logf, "[HOOK] worker_libevent role marker in %s\n",
                IMG_Name(img).c_str());
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);
}

// Helper gia ta global variables sto main executable
// Κρατάμε μόνο τις writable global sections (.data, .bss) για να έχουμε καλύτερη κάλυψη και λιγότερο θόρυβο.
/*static VOID TrackImageGlobals(IMG img)
{
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return;

    THREADID tid = PIN_ThreadId();

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        std::string sname = SEC_Name(sec);

        // κράτα μόνο writable global sections
        if (sname != ".data" && sname != ".bss")
            continue;

        ADDRINT start = SEC_Address(sec);
        size_t size = (size_t)SEC_Size(sec);

        if (start == 0 || size == 0)
            continue;

        Region r;
        r.start = start;
        r.size = size;
        r.tag = (sname == ".data") ? "global:data" : "global:bss";
        r.alloc_file = IMG_Name(img);
        r.alloc_line = 0;

        bool overlapFound = false;
        Region ov;

        PIN_GetLock(&g_regions_lock, tid);
        overlapFound = OverlapsLiveRegion_Locked(r.start, r.size, ov);
        if (!overlapFound) {
            g_regions[r.start] = r;
        }
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            if (!overlapFound) {
                fprintf(g_logf,
                        "[GLOBAL_REGION] tag=%s start=%p size=%zu img=%s sec=%s\n",
                        r.tag.c_str(),
                        (void*)r.start,
                        r.size,
                        IMG_Name(img).c_str(),
                        sname.c_str());
            } else {
                fprintf(g_logf,
                        "[GLOBAL_REGION_OVERLAP] tag=%s start=%p size=%zu overlap_start=%p overlap_size=%zu overlap_tag=%s img=%s sec=%s\n",
                        r.tag.c_str(),
                        (void*)r.start,
                        r.size,
                        (void*)ov.start,
                        ov.size,
                        ov.tag.c_str(),
                        IMG_Name(img).c_str(),
                        sname.c_str());
            }
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
}*/

static VOID TrackImageGlobals(IMG img)
{
    //if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return;
    if (!KnobTraceGlobals.Value()) return;
    if (!IMG_Valid(img)) return;

    THREADID tid = PIN_ThreadId();

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {

        // skip executable sections (.text)
        if (SEC_IsExecutable(sec))
            continue;

        ADDRINT start = SEC_Address(sec);
        size_t size = (size_t)SEC_Size(sec);

        if (start == 0 || size == 0)
            continue;

        std::string sname = SEC_Name(sec);

        Region r;
        r.start = start;
        r.size = size;
        r.tag = "global:" + sname;
        r.alloc_file = IMG_Name(img);
        r.alloc_line = 0;

        bool overlapFound = false;
        Region ov;

        PIN_GetLock(&g_regions_lock, tid);
        overlapFound = OverlapsLiveRegion_Locked(r.start, r.size, ov);
        if (!overlapFound) {
            g_regions[r.start] = r;
        }
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            if (!overlapFound) {
                fprintf(g_logf,
                        "[GLOBAL_REGION] tag=%s start=%p size=%zu img=%s sec=%s\n",
                        r.tag.c_str(),
                        (void*)r.start,
                        r.size,
                        IMG_Name(img).c_str(),
                        sname.c_str());
            }
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
}

//debug msg
static VOID DebugLogSymbol(IMG img, const char* kind, const char* sym, RTN r, const char* extra = "")
{
    PIN_GetLock(&g_events_lock, 0);
    if (g_logf) {
        if (RTN_Valid(r)) {
            fprintf(g_logf,
                    "[FOUND] kind=%s sym=%s addr=%p img=%s %s\n",
                    kind,
                    sym,
                    (void*)RTN_Address(r),
                    IMG_Name(img).c_str(),
                    extra ? extra : "");
        } else {
            fprintf(g_logf,
                    "[MISS ] kind=%s sym=%s img=%s %s\n",
                    kind,
                    sym,
                    IMG_Name(img).c_str(),
                    extra ? extra : "");
        }
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);
}


//enimerwnoume ta malloc/calloc/realloc/free tis libc an to knob einai energopoihmeno.
static VOID HookLibcAllocators(IMG img) {
    if (!KnobUseLibcHooks.Value()) return;
    //if (IMG_Type(img) != IMG_TYPE_SHAREDLIB) return;

    // Προαιρετικό αλλά χρήσιμο: κάνε hook μόνο στη libc
    // (μειώνει θόρυβο αν άλλα libs έχουν "malloc" symbols)
    //const string imgName = IMG_Name(img);
    //if (imgName.find("libc.so") == string::npos) return;

    const string imgName = IMG_Name(img);
    // DEBUG: τύπωσε όλα τα RTNs που μοιάζουν με realloc
    for (SEC s = IMG_SecHead(img); SEC_Valid(s); s = SEC_Next(s)) {
        for (RTN r = SEC_RtnHead(s); RTN_Valid(r); r = RTN_Next(r)) {
            std::string raw = RTN_Name(r);
            if (raw.empty()) continue;

            std::string base = BaseSym(raw);

            if (raw.find("realloc") != std::string::npos ||
                base.find("realloc") != std::string::npos) {
                PIN_GetLock(&g_events_lock, 0);
                if (g_logf) {
                    fprintf(g_logf,
                            "[REALLOC_RTN] raw=%s base=%s img=%s addr=%p plt=%d\n",
                            raw.c_str(),
                            base.c_str(),
                            imgName.c_str(),
                            (void*)RTN_Address(r),
                            IsPltStub(raw) ? 1 : 0);
                    fflush(g_logf);
                }
                PIN_ReleaseLock(&g_events_lock);
            }
        }
    }
    //if (imgName.find("libc.so") == string::npos) return;
    //if (imgName.find("/pin/") != string::npos) return;
    //if (imgName.find("ld-linux") != string::npos) return;
   // if (imgName.find("libpindwarf") != string::npos) return;
    //if (imgName.find("pin") != string::npos && imgName.find("/pin/") != string::npos) return;

     // Hook ΜΟΝΟ σε allocator-related libs για να μην πιάνεις stubs / άσχετα symbols
     bool is_libc     = (imgName.find("libc.so") != string::npos);
     bool is_jemalloc = (imgName.find("jemalloc") != string::npos);
     bool is_tcmalloc = (imgName.find("tcmalloc") != string::npos);
 
     bool is_ld = (imgName.find("ld-linux") != string::npos);
     if (!(is_libc || is_jemalloc || is_tcmalloc || is_ld)) return;
     //if (!(is_libc || is_jemalloc || is_tcmalloc)) return;
     InitAllocatorProtosOnce();
 
    // summary ton candidate symbols gia debugging - DEBUG
    PIN_GetLock(&g_events_lock, 0);
    if (g_logf) {
        fprintf(g_logf,
                "[HOOK_SCAN_BEGIN] img=%s is_libc=%d is_jemalloc=%d is_tcmalloc=%d is_ld=%d\n",
                imgName.c_str(),
                (int)is_libc, (int)is_jemalloc, (int)is_tcmalloc, (int)is_ld);
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);


    auto LogHook = [&](const char* what) {
        PIN_GetLock(&g_events_lock, 0);
        if (g_logf) { fprintf(g_logf, "[HOOK] %s in %s\n", what, imgName.c_str()); fflush(g_logf); }
        PIN_ReleaseLock(&g_events_lock);
    };


    /*auto ReplaceCalloc = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        //RTN_Open(r);
    
        // Κάνε replace: το g_origCalloc θα κρατήσει το original entry
        g_origCalloc = RTN_ReplaceSignature(
            r, AFUNPTR(Calloc_Replacement),
            IARG_PROTOTYPE, g_pCalloc,
            IARG_CONTEXT,
            IARG_THREAD_ID,
            IARG_ORIG_FUNCPTR,           // dinei to original wrapper
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_RETURN_IP,
            IARG_END
        );
    
        //RTN_Close(r);
        //BumpInstalledSymbol(sym); //Symbols_29/3

        LogHook(sym);
        return true;
    };*/

    auto ReplaceCalloc = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        DebugLogSymbol(img, "calloc-replace-candidate", sym, r);
    
        if (!RTN_Valid(r)) return false;
    
        if (!TryMarkHooked(r)) {
            PIN_GetLock(&g_events_lock, 0);
            if (g_logf) {
                fprintf(g_logf,
                        "[SKIP_ALREADY_HOOKED] kind=calloc-replace sym=%s addr=%p img=%s\n",
                        sym,
                        (void*)RTN_Address(r),
                        IMG_Name(img).c_str());
                fflush(g_logf);
            }
            PIN_ReleaseLock(&g_events_lock);
            return false;
        }
    
        PIN_GetLock(&g_events_lock, 0);
        if (g_logf) {
            fprintf(g_logf,
                    "[TRY_REPLACE] kind=calloc sym=%s addr=%p img=%s\n",
                    sym,
                    (void*)RTN_Address(r),
                    IMG_Name(img).c_str());
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
    
        g_origCalloc = RTN_ReplaceSignature(
            r, AFUNPTR(Calloc_Replacement),
            IARG_PROTOTYPE, g_pCalloc,
            IARG_CONTEXT,
            IARG_THREAD_ID,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_RETURN_IP,
            IARG_END
        );
    
        PIN_GetLock(&g_events_lock, 0);
        if (g_logf) {
            fprintf(g_logf,
                    "[REPLACED] kind=calloc sym=%s addr=%p img=%s orig=%p\n",
                    sym,
                    (void*)RTN_Address(r),
                    IMG_Name(img).c_str(),
                    (void*)g_origCalloc);
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
    
        LogHook(sym);
        return true;
    };

    auto ReplaceRealloc = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;

        g_origRealloc = RTN_ReplaceSignature(
            r, AFUNPTR(Realloc_Replacement),
            IARG_PROTOTYPE, g_pRealloc,
            IARG_CONTEXT,
            IARG_THREAD_ID,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,   // oldp
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,   // size
            IARG_RETURN_IP,
            IARG_END
        );

        //BumpInstalledSymbol(sym);
        LogHook(sym);
        return true;
    };

    auto HookMallocLike = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
    
        // BEFORE: store size + caller
        RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeMallocTLS),
            IARG_THREAD_ID,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,   // size
            IARG_RETURN_IP,
            IARG_END);
    
        // AFTER: use ret only
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMallocTLS),
            IARG_THREAD_ID,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);
    
        RTN_Close(r);
        //BumpInstalledSymbol(sym); //Symbols_29/3
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
        //BumpInstalledSymbol(sym);
        LogHook(sym);
        return true;
    };
    

    /*auto HookCallocLikeTLS = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
    
        RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeCallocTLS),
            IARG_THREAD_ID,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,   // n
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,   // size
            IARG_RETURN_IP,
            IARG_END);
    
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterCallocTLS),
            IARG_THREAD_ID,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);
    
        RTN_Close(r);
        LogHook(sym);
        return true;
    };*/

    auto HookCallocLikeTLS = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        DebugLogSymbol(img, "calloc-tls-candidate", sym, r);
    
        if (!RTN_Valid(r)) return false;
    
        if (!TryMarkHooked(r)) {
            PIN_GetLock(&g_events_lock, 0);
            if (g_logf) {
                fprintf(g_logf,
                        "[SKIP_ALREADY_HOOKED] kind=calloc-tls sym=%s addr=%p img=%s\n",
                        sym,
                        (void*)RTN_Address(r),
                        IMG_Name(img).c_str());
                fflush(g_logf);
            }
            PIN_ReleaseLock(&g_events_lock);
            return false;
        }
    
        PIN_GetLock(&g_events_lock, 0);
        if (g_logf) {
            fprintf(g_logf,
                    "[TRY_HOOK] kind=calloc-tls sym=%s addr=%p img=%s\n",
                    sym,
                    (void*)RTN_Address(r),
                    IMG_Name(img).c_str());
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
    
        RTN_Open(r);
    
        RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeCallocTLS),
            IARG_THREAD_ID,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_RETURN_IP,
            IARG_END);
    
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterCallocTLS),
            IARG_THREAD_ID,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);
    
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    

    auto HookReallocLikeTLS = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
    
        RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeReallocTLS),
            IARG_THREAD_ID,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,   // oldp
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,   // size
            IARG_RETURN_IP,
            IARG_END);
    
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterReallocTLS),
            IARG_THREAD_ID,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);
    
        RTN_Close(r);
        LogHook(sym);
        return true;
    };
    

    auto HookReallocarrayLikeTLS = [&](const char* sym) {
        RTN r = RTN_FindByName(img, sym);
        if (!RTN_Valid(r)) return false;
        if (!TryMarkHooked(r)) return false;
    
        RTN_Open(r);
    
        RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeReallocarrayTLS),
            IARG_THREAD_ID,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,   // oldp
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,   // nmemb
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,   // elemsz
            IARG_RETURN_IP,
            IARG_END);
    
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterReallocarrayTLS),
            IARG_THREAD_ID,
            IARG_FUNCRET_EXITPOINT_VALUE,
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


        // ---------------- Deterministic hooks (with PROTOTYPE) ----------------

    // malloc aliases
    for (const char* sym : {
        "malloc", "__libc_malloc", "__GI___libc_malloc",
        "__GI_malloc"
    }) {
        //HookAfterMallocLike(sym);
        HookMallocLike(sym);
    }

    // free aliases
    for (const char* sym : {
        "free", "__libc_free", "__GI___libc_free",
        "cfree", "__libc_cfree",
        "__GI_free"
    }) {
        HookBeforeFreeLike(sym);
    }


    // calloc: κάνε replace (όχι TLS BEFORE/AFTER)
    bool replaced = false;

    // Πρώτα προσπάθησε τα πιο “σωστά”/συχνά
    for (const char* sym : {
        "__libc_calloc",
        "__GI___libc_calloc",
        "calloc",
        "__GI_calloc"
    }) {
        if (ReplaceCalloc(sym)) { replaced = true; break; }
    }

    if (!replaced) {
        // προαιρετικό log ότι δεν βρέθηκε calloc symbol
        PIN_GetLock(&g_events_lock, 0);
        if (g_logf) {
            fprintf(g_logf, "[WARN] Δεν βρέθηκε calloc για replace μέσα στο %s\n", imgName.c_str());
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
    }

    // realloc aliases
    /*for (const char* sym : {
        "realloc", "__libc_realloc", "__GI___libc_realloc",
        "__GI_realloc"
    }) {
        HookReallocLikeTLS(sym);
    }*/

    // realloc aliases -> κάνε replace, όχι BEFORE/AFTER TLS
    bool replaced_realloc = false;

    for (const char* sym : {
        "__libc_realloc",
        "__GI___libc_realloc",
        "realloc",
        "__GI_realloc"
    }) {
        if (ReplaceRealloc(sym)) {
            replaced_realloc = true;
            break;
        }
    }

    if (!replaced_realloc) {
        PIN_GetLock(&g_events_lock, 0);
        if (g_logf) {
            fprintf(g_logf, "[WARN] Δεν βρέθηκε realloc για replace μέσα στο %s\n", imgName.c_str());
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
    }

    // reallocarray aliases
    for (const char* sym : {
        "reallocarray", "__libc_reallocarray", "__GI___libc_reallocarray"
    }) {
        HookReallocarrayLikeTLS(sym);
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
    for (const char* sym : { "je_malloc" }) {
        HookMallocLike(sym);
    }
    for (const char* sym : { "je_free" }) {
        HookBeforeFreeLike(sym);
    }
    for (const char* sym : { "je_calloc" }) {
        HookCallocLikeTLS(sym);
    }
    for (const char* sym : { "je_realloc" }) {
        HookReallocLikeTLS(sym);
    }
    for (const char* sym : { "je_reallocarray" }) {
        HookReallocarrayLikeTLS(sym);
    }

    
        // ---------------- mmap/munmap/mremap hooks ----------------
    {
    // mmap variants
    //for (const char* sym : {"mmap", "mmap64", "__mmap"}) {
    /*for (const char* sym : {"mmap", "mmap64", "__mmap", "__mmap64", "__GI___mmap", "__GI___mmap64"}) {
        RTN r = RTN_FindByName(img, sym);
        if (RTN_Valid(r) && TryMarkHooked(r)) {
            RTN_Open(r);
            // mmap(addr, length, prot, flags, fd, offset) -> ret
            RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeMmapTLS),
            IARG_THREAD_ID,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,   // length
            IARG_RETURN_IP,
            IARG_END);
        
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMmapTLS),
            IARG_THREAD_ID,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);
            RTN_Close(r);
            LogHook(sym);
        }
    }*/

    for (const char* sym : {"mmap", "mmap64", "__mmap", "__mmap64", "__GI___mmap", "__GI___mmap64"}) {
        RTN r = RTN_FindByName(img, sym);
        DebugLogSymbol(img, "mmap-candidate", sym, r);
    
        if (!RTN_Valid(r)) continue;
    
        if (!TryMarkHooked(r)) {
            PIN_GetLock(&g_events_lock, 0);
            if (g_logf) {
                fprintf(g_logf,
                        "[SKIP_ALREADY_HOOKED] kind=mmap sym=%s addr=%p img=%s\n",
                        sym,
                        (void*)RTN_Address(r),
                        IMG_Name(img).c_str());
                fflush(g_logf);
            }
            PIN_ReleaseLock(&g_events_lock);
            continue;
        }
    
        PIN_GetLock(&g_events_lock, 0);
        if (g_logf) {
            fprintf(g_logf,
                    "[TRY_HOOK] kind=mmap sym=%s addr=%p img=%s\n",
                    sym,
                    (void*)RTN_Address(r),
                    IMG_Name(img).c_str());
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
    
        RTN_Open(r);
        RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeMmapTLS),
            IARG_THREAD_ID,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_RETURN_IP,
            IARG_END);
    
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMmapTLS),
            IARG_THREAD_ID,
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);
        RTN_Close(r);
        LogHook(sym);
    }

    // munmap variants
    //for (const char* sym : {"munmap", "__munmap"}) {
    for (const char* sym : {"munmap", "__munmap", "__GI___munmap"}) {
        RTN r = RTN_FindByName(img, sym);
        if (RTN_Valid(r) && TryMarkHooked(r)) {
            RTN_Open(r);
            // munmap(addr, length) -> int rc
            RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeMunmapTLS),
    IARG_THREAD_ID,
    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,   // addr
    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,   // length
    IARG_RETURN_IP,
    IARG_END);

RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMunmapTLS),
    IARG_THREAD_ID,
    IARG_FUNCRET_EXITPOINT_VALUE,       // rc
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
            RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeMremapTLS),
    IARG_THREAD_ID,
    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,   // oldp
    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,   // oldsz
    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,   // newsz
    IARG_RETURN_IP,
    IARG_END);

    RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMremapTLS),
        IARG_THREAD_ID,
        IARG_FUNCRET_EXITPOINT_VALUE,
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


    //debug
    PIN_GetLock(&g_events_lock, 0);
    if (g_logf) {
        fprintf(g_logf, "[HOOK_SCAN_END] img=%s\n", imgName.c_str());
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

}

// -------------------------- Image load ---------------------------
// kanume hook tis routines gia ta dummy sites kai gia ta libc malloc/free an einai energopoihmeno to knob.
static VOID ImageLoad(IMG img, VOID*) {
    HookDummySites(img);       // your __memtrace_* if present
    HookLibcAllocators(img);   // optional libc hooks (knob)
    HookMemcachedThreadRoles(img); // worker role labeling
    TrackImageGlobals(img);    // track globals in main executable

}

// ----------------------- Thread lifecycle ------------------------

/*static VOID ThreadStart(THREADID tid, CONTEXT*, INT32, VOID*) {
    ThreadCtx* tc = new ThreadCtx();
    //tc->out = nullptr; // δεν χρησιμοποιείται πλέον
    tc->owner_tid = tid;
    PIN_SetThreadData(g_tls_key, tc, tid);
}*/
// Vazw sto ThreadStart to os_tid kai το role, και logarw sto thread start. 
static VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32, VOID*) {
    ThreadCtx* tc = new ThreadCtx();
    tc->owner_tid = tid;
    tc->os_tid = PIN_GetTid();
    tc->role = ROLE_OTHER;   // default: non-worker μέχρι να αποδειχθεί worker
    PIN_SetThreadData(g_tls_key, tc, tid);

    PIN_GetLock(&g_events_lock, tid);
    if (g_logf) {
        fprintf(g_logf,
                "[THREAD_START] pin_tid=%u os_tid=%d role=%s\n",
                (unsigned)tid, (int)tc->os_tid, ThreadRoleStr(tc->role));
        fflush(g_logf);
    }
    PIN_ReleaseLock(&g_events_lock);

        // Approximate per-thread stack region
        ADDRINT sp = 0;

        #if defined(TARGET_IA32E)
            sp = PIN_GetContextReg(ctxt, REG_RSP);
        #else
            sp = PIN_GetContextReg(ctxt, REG_ESP);
        #endif
        
            const size_t kApproxStackSize = 8 * 1024 * 1024; // 8MB
        
            Region sr;
            sr.start = (sp > kApproxStackSize) ? (sp - kApproxStackSize) : 0;
            sr.size  = (sp > kApproxStackSize) ? kApproxStackSize : (size_t)sp;
            sr.tag   = "stack";
            sr.alloc_file = "STACK";
            sr.alloc_line = 0;
        
            PIN_GetLock(&g_stack_lock, tid);
            g_stack_regions[tid] = sr;
            PIN_ReleaseLock(&g_stack_lock);
        
            PIN_GetLock(&g_events_lock, tid);
            if (g_logf) {
                fprintf(g_logf,
                        "[STACK_INIT] T%u stack_start=%p stack_size=%zu sp=%p\n",
                        (unsigned)tid,
                        (void*)sr.start,
                        sr.size,
                        (void*)sp);
                fflush(g_logf);
            }
            PIN_ReleaseLock(&g_events_lock);
}

static VOID ThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*) {
    ThreadCtx* tc = CTX(tid);
    if (tc) {
        // ✅ αν έμειναν pending calloc entries, τύπωσε τα
        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            fprintf(g_logf, "[FINI] T%u pendingCallocTop=%d\n",
                    (unsigned)tid, tc->pendingCallocTop);
            for (int i = 0; i < tc->pendingCallocTop; i++) {
                const auto& p = tc->pendingCallocStack[i];
                fprintf(g_logf,
                        "  [FINI-PENDING] i=%d seq=%llu n=%zu sz=%zu ip=%p\n",
                        i, (unsigned long long)p.seq,
                        (size_t)p.n, (size_t)p.sz,
                        (void*)p.callerIp);
            }
            fflush(g_logf);
        }
        PIN_ReleaseLock(&g_events_lock);
        // thread summary
        PIN_GetLock(&g_events_lock, tid);
        if (g_logf) {
            fprintf(g_logf,
            "[THREAD_FINI] pin_tid=%u os_tid=%d role=%s\n",
            (unsigned)tid, (int)tc->os_tid, ThreadRoleStr(tc->role));
        fflush(g_logf);
        }

PIN_ReleaseLock(&g_events_lock);

        // Clean up stack region for this thread
        PIN_GetLock(&g_stack_lock, tid);
        g_stack_regions.erase(tid);
        PIN_ReleaseLock(&g_stack_lock);

        delete tc;
        PIN_SetThreadData(g_tls_key, nullptr, tid);
    }
}

// ----------------------------- Fini ------------------------------
// Global fini: κλείνει τα global αρχεία log/events/trace
static VOID Fini(INT32, VOID*) {
    PIN_GetLock(&g_events_lock, 0);
    if (tracef) {
        //fprintf(tracef, "#eof\n");
        fclose(tracef);
        tracef = nullptr;
    }
    if (eventsf) {
        fprintf(eventsf, "#eof\n");
        fclose(eventsf);
        eventsf = nullptr;
    }
    if (g_logf) {
        fclose(g_logf);
        g_logf = nullptr;
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
int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;

    PIN_InitLock(&g_regions_lock);
    PIN_InitLock(&g_stack_lock);
    PIN_InitLock(&g_events_lock);
    PIN_InitLock(&g_hook_lock);
    PIN_InitLock(&g_src_cache_lock);
    //PIN_InitLock(&g_stats_lock);

    g_tls_key = PIN_CreateThreadDataKey(nullptr);

    // ΝΕΟ: Άνοιξε τα αρχεία ΠΡΙΝ το ParseProcMaps
    g_logf    = fopen("pintool.log", "w");
    eventsf = fopen("pinatrace.events", "w");
    tracef  = fopen("pinatrace.out", "w");

    if (g_logf) {
        fprintf(g_logf, "[START] pid=%d g_trace_memops=%d\n", getpid(), (int)g_trace_memops);
        fflush(g_logf);
    }
    if (tracef) {
        //fprintf(tracef, "#TOOL mytool_version=BASELINE_ONLY_ALLOCFREE\n");
        //fprintf(tracef, "#START pid=%d g_trace_memops=%d\n", getpid(), (int)g_trace_memops);
        fflush(tracef);
    }

    // Parse pre-existing allocations (ΜΕΤΑ τα αρχεία)
    //ParseProcMaps();

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