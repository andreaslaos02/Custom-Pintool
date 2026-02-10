//aftos o kwdikas exei filters gia na perni ta alloc tou memcached alla oxi ta load&stores

#include "pin.H"
#include <map>
#include <string>
#include <cstdio>
#include <cstdint>
#include <unistd.h>   // getpid
#include <set>
#include <signal.h>

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
static VOID RecordRead(THREADID tid, VOID* ip, VOID* ea) {
    if (!tracef) return;
    if (!g_trace_memops) return;
    const ADDRINT a = (ADDRINT)ea;
    Region snap;
    size_t off = 0;

    if (!FindRegionWithOff(a, snap, off)) return;
    if (off >= snap.size) return;

    PIN_GetLock(&g_events_lock, tid);
    /*fprintf(tracef, "T%u %p: load  %p tag=%s off=%zu\n",
            (unsigned)tid, ip, (void*)a, snap.tag.c_str(), off);*/
    fprintf(tracef,
            "T%u %p: load  base: %p full: %p tag=%s off=%zu\n",
            (unsigned)tid, ip,
            (void*)snap.start, (void*)a,
            snap.tag.c_str(), off);
    PIN_ReleaseLock(&g_events_lock);
}

static VOID RecordWrite(THREADID tid, VOID* ip, VOID* ea) {
    if (!tracef) return;
    if (!g_trace_memops) return;
    const ADDRINT a = (ADDRINT)ea;
    Region snap;
    size_t off = 0;

    if (!FindRegionWithOff(a, snap, off)) return;
    if (off >= snap.size) return;

    PIN_GetLock(&g_events_lock, tid);
    /*fprintf(tracef, "T%u %p: store %p tag=%s off=%zu\n",
            (unsigned)tid, ip, (void*)a, snap.tag.c_str(), off);*/
    fprintf(tracef,
                "T%u %p: store base: %p full: %p tag=%s off=%zu\n",
                (unsigned)tid, ip,
                (void*)snap.start, (void*)a,
                snap.tag.c_str(), off);
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
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(RecordRead),
                IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA, i, IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, i)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(RecordWrite),
                IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA, i, IARG_END);
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

    // Debug για να δούμε αν ΠΟΤΕ μπαίνουμε εδώ
    /*fprintf(stderr, "[Pintool] CallAllocSite: T%u ptr=%p size=%zu tag=%s func=%s file=%s line=%d\n",
            (unsigned)tid,
            ptr,
            size,
            type_tag ? type_tag : "?",
            func ? func : "?",
            file ? file : "?",
            line);*/

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

    // Debug για να δούμε αν μπαίνουμε εδώ
    /*fprintf(stderr, "[Pintool] CallFreeSite: T%u ptr=%p tag=%s func=%s file=%s line=%d\n",
            (unsigned)tid,
            ptr,
            type_tag ? type_tag : "?",
            func ? func : "?",
            file ? file : "?",
            line);*/

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
/*
static VOID AfterMalloc(ADDRINT ret, size_t sz, ADDRINT caller_ip) {
    if (!ret || sz == 0) return;
    THREADID tid = PIN_ThreadId();

    PIN_GetLock(&g_regions_lock, tid);
    Region r; r.start = ret; r.size = sz; r.tag = "heap";
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);
    if (eventsf) {
        fprintf(eventsf,
                "alloc start=%p size=%zu tag=heap site=libc:malloc pc=%p\n",
                (void*)ret, sz, (void*)caller_ip);
        fflush(eventsf);
    }
    if (tracef) {
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=heap site=libc:malloc pc=%p\n",
                (unsigned)tid, (void*)ret, sz, (void*)caller_ip);
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}

static VOID AfterCalloc(ADDRINT ret, size_t n, size_t sz, ADDRINT caller_ip) {
    if (!ret || n == 0 || sz == 0) return;
    size_t bytes = n * sz;
    THREADID tid = PIN_ThreadId();

    PIN_GetLock(&g_regions_lock, tid);
    Region r; r.start = ret; r.size = bytes; r.tag = "heap:calloc";
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);
    if (eventsf) {
        fprintf(eventsf,
                "alloc start=%p size=%zu tag=heap:calloc site=libc:calloc pc=%p\n",
                (void*)ret, bytes, (void*)caller_ip);
        fflush(eventsf);
    }
    if (tracef) {
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=heap:calloc site=libc:calloc pc=%p\n",
                (unsigned)tid, (void*)ret, bytes, (void*)caller_ip);
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}

static VOID AfterRealloc(ADDRINT ret, ADDRINT oldp, size_t sz, ADDRINT caller_ip) {
    THREADID tid = PIN_ThreadId();

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
                        "free  start=%p size=%zu tag=%s site=libc:realloc(old) pc=%p\n",
                        (void*)snap.start, snap.size, snap.tag.c_str(), (void*)caller_ip);
            } else {
                fprintf(eventsf,
                        "free  start=%p tag=UNKNOWN site=libc:realloc(old) pc=%p\n",
                        (void*)oldp, (void*)caller_ip);
            }
            fflush(eventsf);
        }
        if (tracef) {
            if (known) {
                fprintf(tracef,
                        "T%u free  start=%p size=%zu tag=%s site=libc:realloc(old) pc=%p\n",
                        (unsigned)tid, (void*)snap.start, snap.size, snap.tag.c_str(), (void*)caller_ip);
            } else {
                fprintf(tracef,
                        "T%u free  start=%p tag=UNKNOWN site=libc:realloc(old) pc=%p\n",
                        (unsigned)tid, (void*)oldp, (void*)caller_ip);
            }
            fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }

    // new allocation
    if (ret && sz) {
        PIN_GetLock(&g_regions_lock, tid);
        Region r; r.start = ret; r.size = sz; r.tag = "heap:realloc";
        g_regions[ret] = r;
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (eventsf) {
            fprintf(eventsf,
                    "alloc start=%p size=%zu tag=heap:realloc site=libc:realloc pc=%p\n",
                    (void*)ret, sz, (void*)caller_ip);
            fflush(eventsf);
        }
        if (tracef) {
            fprintf(tracef,
                    "T%u alloc start=%p size=%zu tag=heap:realloc site=libc:realloc pc=%p\n",
                    (unsigned)tid, (void*)ret, sz, (void*)caller_ip);
            fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
}*/

static VOID AfterMalloc(ADDRINT ret, size_t sz, ADDRINT caller_ip) {
    if (!ret || sz == 0) return;
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
    Region r; r.start = ret; r.size = sz; r.tag = "heap";
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);
    if (eventsf) {
        fprintf(eventsf,
                "alloc start=%p size=%zu tag=heap site=%s:%d img=%s+0x%lx pc=%p\n",
                (void*)ret, sz,
                srcFileC, (int)srcLine,
                imgC, (unsigned long)imgOff,
                (void*)caller_ip);
        fflush(eventsf);
    }
    if (tracef) {
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=heap site=%s:%d img=%s+0x%lx pc=%p\n",
                (unsigned)tid, (void*)ret, sz,
                srcFileC, (int)srcLine,
                imgC, (unsigned long)imgOff,
                (void*)caller_ip);
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}

static VOID AfterCalloc(ADDRINT ret, size_t n, size_t sz, ADDRINT caller_ip) {
    if (!ret || n == 0 || sz == 0) return;
    size_t bytes = n * sz;
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
    if (eventsf) {
        fprintf(eventsf,
                "alloc start=%p size=%zu tag=heap:calloc site=%s:%d img=%s+0x%lx pc=%p\n",
                (void*)ret, bytes,
                srcFileC, (int)srcLine,
                imgC, (unsigned long)imgOff,
                (void*)caller_ip);
        fflush(eventsf);
    }
    if (tracef) {
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=heap:calloc site=%s:%d img=%s+0x%lx pc=%p\n",
                (unsigned)tid, (void*)ret, bytes,
                srcFileC, (int)srcLine,
                imgC, (unsigned long)imgOff,
                (void*)caller_ip);
        fflush(tracef);
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
                fprintf(tracef,
                        "T%u free  start=%p size=%zu tag=%s site=%s:%d img=%s+0x%lx pc=%p\n",
                        (unsigned)tid,
                        (void*)snap.start, snap.size, snap.tag.c_str(),
                        srcFileC, (int)srcLine,
                        imgC, (unsigned long)imgOff,
                        (void*)caller_ip);
            } else {
                fprintf(tracef,
                        "T%u free  start=%p tag=UNKNOWN site=%s:%d img=%s+0x%lx pc=%p\n",
                        (unsigned)tid,
                        (void*)oldp,
                        srcFileC, (int)srcLine,
                        imgC, (unsigned long)imgOff,
                        (void*)caller_ip);
            }
            fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }

    // new allocation
    if (ret && sz) {
        PIN_GetLock(&g_regions_lock, tid);
        Region r; r.start = ret; r.size = sz; r.tag = "heap:realloc";
        g_regions[ret] = r;
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (eventsf) {
            fprintf(eventsf,
                    "alloc start=%p size=%zu tag=heap:realloc site=%s:%d img=%s+0x%lx pc=%p\n",
                    (void*)ret, sz,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
            fflush(eventsf);
        }
        if (tracef) {
            fprintf(tracef,
                    "T%u alloc start=%p size=%zu tag=heap:realloc site=%s:%d img=%s+0x%lx pc=%p\n",
                    (unsigned)tid, (void*)ret, sz,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
            fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
}

static bool FindRegionWithOff(ADDRINT a, Region &out, size_t &off)
{
    bool found = false;
    PIN_GetLock(&g_regions_lock, PIN_ThreadId());
    auto it = g_regions.upper_bound(a);
    if (it != g_regions.begin()) {
        --it;
        const Region &r = it->second;
        if (a >= r.start && a < (r.start + r.size)) {
            out = r;
            off = (size_t)(a - r.start);        //return offset here instead of calculatig in RecordRead/Write.
            found = true;
        }
    }
    PIN_ReleaseLock(&g_regions_lock);
    return found;
}

/*static VOID BeforeFree(ADDRINT p, ADDRINT caller_ip) {
    if (!p) return;
    THREADID tid = PIN_ThreadId();

    // debugging for frees
    std::string srcFile;
    INT32 srcLine = 0, srcCol = 0;
    GetSrcFromIp(caller_ip, srcFile, srcLine, srcCol);
    const char* srcFileC = srcFile.empty() ? "?" : srcFile.c_str();

    bool known_exact = false;
    bool known_inside = false;
    //bool erased = false;
    Region snap;
    size_t off = 0;

    PIN_GetLock(&g_regions_lock, tid);

    // 1) exact start
    auto it = g_regions.find(p);
    if (it != g_regions.end()) {
        snap = it->second;
        known_exact = true;
        g_regions.erase(it);
        //erased = true;
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

                // IMPORTANT:
                // δεν κάνουμε erase εδώ, γιατί δεν ξέρουμε ποιο είναι το real start που πρέπει να φύγει
                // (αν θες, θα το κάνουμε ως ANOMALY χωρίς erase)
            }
        }
    }

    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);

    if (eventsf) {
        if (known_exact) {
            fprintf(eventsf, "free  start=%p size=%zu tag=%s site=libc:free pc=%p\n",
                    (void*)snap.start, snap.size, snap.tag.c_str(),(void*)caller_ip);
        } else if (known_inside) {
            fprintf(eventsf,
                    "ANOMALY free_interior ptr=%p inside_start=%p inside_size=%zu inside_tag=%s off=%zu site=libc:free pc=%p\n",
                    (void*)p, (void*)snap.start, snap.size, snap.tag.c_str(), off, (void*)caller_ip);
        } else {
            //fprintf(eventsf, "free  start=%p tag=? site=libc:free\n", (void*)p);
            fprintf(eventsf, "free  start=%p tag=UNKNOWN site=libc:free pc=%p\n", (void*)p, (void*)caller_ip);
        }
        fflush(eventsf);
    }

    if (tracef) {
        if (known_exact) {
            fprintf(tracef,
                    "T%u free  start=%p size=%zu tag=%s site=libc:free pc=%p\n",
                    (unsigned)tid, (void*)snap.start, snap.size, snap.tag.c_str(), (void*)caller_ip);
        } else if (known_inside) {
            fprintf(tracef,
                    "T%u ANOMALY free_interior ptr=%p inside_start=%p inside_size=%zu inside_tag=%s off=%zu site=libc:free pc=%p\n",
                    (unsigned)tid, (void*)p, (void*)snap.start, snap.size, snap.tag.c_str(), off, (void*)caller_ip);
        } else {
            fprintf(tracef,
                    "T%u free  start=%p tag=? site=libc:free pc=%p\n",
                    (unsigned)tid, (void*)p, (void*)caller_ip);
        }
        fflush(tracef);
    }

    PIN_ReleaseLock(&g_events_lock);
}*/

static VOID BeforeFree(ADDRINT p, ADDRINT caller_ip) {
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

    if (tracef) {
        if (known_exact) {
            fprintf(tracef,
                    "T%u free  start=%p size=%zu tag=%s site=%s:%d img=%s+0x%lx pc=%p\n",
                    (unsigned)tid,
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        } else if (known_inside) {
            fprintf(tracef,
                    "T%u ANOMALY free_interior ptr=%p inside_start=%p inside_size=%zu inside_tag=%s off=%zu site=%s:%d img=%s+0x%lx pc=%p\n",
                    (unsigned)tid,
                    (void*)p, (void*)snap.start, snap.size, snap.tag.c_str(), off,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        } else {
            fprintf(tracef,
                    "T%u free  start=%p tag=UNKNOWN site=%s:%d img=%s+0x%lx pc=%p\n",
                    (unsigned)tid,
                    (void*)p,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
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
    if (!p || sz == 0) return;
    AfterMalloc((ADDRINT)p, sz, caller_ip);
}

// ---------------- mmap/munmap/mremap hooks (with caller pc) ----------------

// mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) -> void*
/*
static VOID AfterMmap(ADDRINT ret, size_t length, ADDRINT caller_ip)
{
    if (!ret || ret == (ADDRINT)-1 || length == 0) return;
    THREADID tid = PIN_ThreadId();

    PIN_GetLock(&g_regions_lock, tid);
    Region r; r.start = ret; r.size = length; r.tag = "mmap";
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);
    if (eventsf) {
        fprintf(eventsf,
                "alloc start=%p size=%zu tag=mmap site=libc:mmap pc=%p\n",
                (void*)ret, length, (void*)caller_ip);
        fflush(eventsf);
    }
    if (tracef) {
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=mmap site=libc:mmap pc=%p\n",
                (unsigned)tid, (void*)ret, length, (void*)caller_ip);
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}

// munmap(void *addr, size_t length) -> int
static VOID AfterMunmap(INT32 rc, ADDRINT addr, size_t length, ADDRINT caller_ip)
{
    if (rc != 0) return;
    if (!addr || length == 0) return;
    THREADID tid = PIN_ThreadId();

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
                    "free  start=%p size=%zu tag=%s site=libc:munmap pc=%p\n",
                    (void*)snap.start, snap.size, snap.tag.c_str(), (void*)caller_ip);
        } else {
            fprintf(eventsf,
                    "free  start=%p tag=? site=libc:munmap pc=%p\n",
                    (void*)addr, (void*)caller_ip);
        }
        fflush(eventsf);
    }
    if (tracef) {
        if (known) {
            fprintf(tracef,
                    "T%u free  start=%p size=%zu tag=%s site=libc:munmap pc=%p\n",
                    (unsigned)tid, (void*)snap.start, snap.size, snap.tag.c_str(), (void*)caller_ip);
        } else {
            fprintf(tracef,
                    "T%u free  start=%p tag=? site=libc:munmap pc=%p\n",
                    (unsigned)tid, (void*)addr, (void*)caller_ip);
        }
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}

// mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...) -> void*
static VOID AfterMremap(ADDRINT ret, ADDRINT oldp, size_t oldsz, size_t newsz, ADDRINT caller_ip)
{
    THREADID tid = PIN_ThreadId();

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
                        "free  start=%p size=%zu tag=%s site=libc:mremap(old) pc=%p\n",
                        (void*)snap_old.start, snap_old.size, snap_old.tag.c_str(), (void*)caller_ip);
            } else {
                fprintf(eventsf,
                        "free  start=%p tag=mmap site=libc:mremap(old) pc=%p\n",
                        (void*)oldp, (void*)caller_ip);
            }
            fflush(eventsf);
        }
        if (tracef) {
            if (known_old) {
                fprintf(tracef,
                        "T%u free  start=%p size=%zu tag=%s site=libc:mremap(old) pc=%p\n",
                        (unsigned)tid, (void*)snap_old.start, snap_old.size, snap_old.tag.c_str(), (void*)caller_ip);
            } else {
                fprintf(tracef,
                        "T%u free  start=%p tag=mmap site=libc:mremap(old) pc=%p\n",
                        (unsigned)tid, (void*)oldp, (void*)caller_ip);
            }
            fflush(tracef);
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
                    "alloc start=%p size=%zu tag=mremap site=libc:mremap pc=%p\n",
                    (void*)ret, newsz, (void*)caller_ip);
            fflush(eventsf);
        }
        if (tracef) {
            fprintf(tracef,
                    "T%u alloc start=%p size=%zu tag=mremap site=libc:mremap pc=%p\n",
                    (unsigned)tid, (void*)ret, newsz, (void*)caller_ip);
            fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
}*/

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
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=mmap site=%s:%d img=%s+0x%lx pc=%p\n",
                (unsigned)tid, (void*)ret, length,
                srcFileC, (int)srcLine,
                imgC, (unsigned long)imgOff,
                (void*)caller_ip);
        fflush(tracef);
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
            fprintf(tracef,
                    "T%u free  start=%p size=%zu tag=%s site=%s:%d img=%s+0x%lx pc=%p\n",
                    (unsigned)tid,
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        } else {
            fprintf(tracef,
                    "T%u free  start=%p tag=UNKNOWN site=%s:%d img=%s+0x%lx pc=%p\n",
                    (unsigned)tid,
                    (void*)addr,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
        }
        fflush(tracef);
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
            if (known_old) {
                fprintf(tracef,
                        "T%u free  start=%p size=%zu tag=%s site=%s:%d img=%s+0x%lx pc=%p\n",
                        (unsigned)tid,
                        (void*)snap_old.start, snap_old.size, snap_old.tag.c_str(),
                        srcFileC, (int)srcLine,
                        imgC, (unsigned long)imgOff,
                        (void*)caller_ip);
            } else {
                fprintf(tracef,
                        "T%u free  start=%p tag=UNKNOWN site=%s:%d img=%s+0x%lx pc=%p\n",
                        (unsigned)tid,
                        (void*)oldp,
                        srcFileC, (int)srcLine,
                        imgC, (unsigned long)imgOff,
                        (void*)caller_ip);
            }
            fflush(tracef);
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
            fprintf(tracef,
                    "T%u alloc start=%p size=%zu tag=mremap site=%s:%d img=%s+0x%lx pc=%p\n",
                    (unsigned)tid,
                    (void*)ret, newsz,
                    srcFileC, (int)srcLine,
                    imgC, (unsigned long)imgOff,
                    (void*)caller_ip);
            fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
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
    if (imgName.find("ld-linux") != string::npos) return;
    if (imgName.find("libpindwarf") != string::npos) return;
    if (imgName.find("pin") != string::npos && imgName.find("/pin/") != string::npos) return;

    auto LogHook = [&](const char* what) {
        PIN_GetLock(&g_events_lock, 0);
        if (logf) { fprintf(logf, "[HOOK] %s in %s\n", what, imgName.c_str()); fflush(logf); }
        PIN_ReleaseLock(&g_events_lock);
    };

    auto HookAfterRet1 = [&](const char* sym, AFUNPTR fn) {
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

    // malloc/calloc/realloc/free — hook both public + __libc_* names
    HookAfterRet1("malloc",        AFUNPTR(AfterMalloc));
    HookAfterRet1("__libc_malloc", AFUNPTR(AfterMalloc));

    // calloc has 2 args
    {
        RTN r = RTN_FindByName(img, "calloc");
        if (RTN_Valid(r)) {
            if (TryMarkHooked(r)) {
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterCalloc),
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                LogHook("calloc");
            }
        }
        r = RTN_FindByName(img, "__libc_calloc");
        if (RTN_Valid(r)) {
            if (TryMarkHooked(r)) {
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterCalloc),
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_RETURN_IP,
                    IARG_END);
                RTN_Close(r);
                LogHook("__libc_calloc");
            }
        }
    }

    // realloc: (oldptr, size)
    {
        RTN r = RTN_FindByName(img, "realloc");
        if (RTN_Valid(r)) {
            if (TryMarkHooked(r)) {
            RTN_Open(r);
            RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterRealloc),
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_RETURN_IP,
                IARG_END);
            RTN_Close(r);
            LogHook("realloc");
            }
        }
        r = RTN_FindByName(img, "__libc_realloc");
        if (RTN_Valid(r)) {
            if (TryMarkHooked(r)) {
            RTN_Open(r);
            RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterRealloc),
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_RETURN_IP,
                IARG_END);
            RTN_Close(r);
            LogHook("__libc_realloc");
            }
        }
    }

    // free: before (ptr)
    HookBefore1("free",        AFUNPTR(BeforeFree));
    HookBefore1("__libc_free", AFUNPTR(BeforeFree));

    // aligned / other allocators
    HookAfterRet2("aligned_alloc", AFUNPTR(AfterAlignedAlloc));
    HookAfterRet2("memalign",      AFUNPTR(AfterMemalign));
    HookAfterRet1("valloc",        AFUNPTR(AfterValloc));
    HookAfterRet1("pvalloc",       AFUNPTR(AfterPvalloc));

    // posix_memalign returns int, writes pointer to *memptr
    {
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
    }
    // ---------------- mmap/munmap/mremap hooks ----------------
{
    // mmap variants
    for (const char* sym : {"mmap", "mmap64", "__mmap"}) {
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
    for (const char* sym : {"munmap", "__munmap"}) {
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
    for (const char* sym : {"mremap", "__mremap"}) {
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
    PIN_ReleaseLock(&g_events_lock);
}


// ------------------------------ main -----------------------------
// dilwnei ta call backs kai arxizei to Pin.
int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;

    PIN_InitLock(&g_regions_lock);
    PIN_InitLock(&g_events_lock);
    PIN_InitLock(&g_hook_lock);

    g_tls_key = PIN_CreateThreadDataKey(nullptr);

    // Global files
    logf    = fopen("pintool.log", "w");
    eventsf = fopen("pinatrace.events", "w");  // κρατάμε το events όπως πριν
    tracef  = fopen("pinatrace.out", "w");     // ΕΝΙΑΙΟ trace file

    if (tracef) {
        fprintf(tracef, "#TOOL mytool_version=BASELINE_ONLY_ALLOCFREE\n");
        fprintf(tracef, "#START pid=%d g_trace_memops=%d\n", getpid(), (int)g_trace_memops);
        fflush(tracef);
    }
    if (logf) {
        fprintf(logf, "[START] pid=%d g_trace_memops=%d\n", getpid(), (int)g_trace_memops);
        fflush(logf);
    }

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