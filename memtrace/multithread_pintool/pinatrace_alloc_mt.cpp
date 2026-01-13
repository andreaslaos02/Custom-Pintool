#include "pin.H"
#include <map>
#include <string>
#include <cstdio>
#include <cstdint>
#include <unistd.h>   // getpid

using std::string;

// ----------------------------- Knobs -----------------------------    //gia hooks se malloc/free libc
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

    ThreadCtx()
        : out(nullptr),
          hasPendingAlloc(false),
          pendingSize(0),
          pendingTypeTag(nullptr),
          pendingFunc(nullptr),
          pendingFile(nullptr),
          pendingLine(0)
    {}
};
static TLS_KEY g_tls_key;

// Helper: fetch per-thread ctx
static inline ThreadCtx* CTX(THREADID tid) {
    return static_cast<ThreadCtx*>(PIN_GetThreadData(g_tls_key, tid));
}

// ------------------------- Lookup helper -------------------------
// Snapshot variant: γεμίζει το out και επιστρέφει true/false.
static bool FindRegion(ADDRINT a, Region &out) {
    bool found = false;
    PIN_GetLock(&g_regions_lock, PIN_ThreadId());
    auto it = g_regions.upper_bound(a);  // first start > a
    if (it != g_regions.begin()) {
        --it;                            // candidate: start <= a
        const Region &r = it->second;
        if (a >= r.start && a < (r.start + r.size)) {      //!r.freed &&
            out = r;                     // snapshot (αντιγράφει και το string)
            found = true;
        }
    }
    PIN_ReleaseLock(&g_regions_lock);
    return found;
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

// --------------------- Record memory accesses --------------------
static VOID RecordRead(THREADID tid, VOID* ip, VOID* ea) {
    if (!tracef) return; // global trace file

    const ADDRINT a = (ADDRINT)ea;
    Region snap;
    if (!FindRegion(a, snap)) return;

    const size_t off = (size_t)(a - snap.start);
    if (off >= snap.size) return;

    // Ένα ενιαίο trace file, προστατευμένο με lock
    PIN_GetLock(&g_events_lock, tid);
    fprintf(tracef, "T%u %p: load  %p tag=%s off=%zu\n",
            (unsigned)tid, ip, (void*)a, snap.tag.c_str(), off);
    PIN_ReleaseLock(&g_events_lock);
}

static VOID RecordWrite(THREADID tid, VOID* ip, VOID* ea) {
    if (!tracef) return;

    const ADDRINT a = (ADDRINT)ea;
    Region snap;
    if (!FindRegion(a, snap)) return;

    const size_t off = (size_t)(a - snap.start);
    if (off >= snap.size) return;

    PIN_GetLock(&g_events_lock, tid);
    fprintf(tracef, "T%u %p: store %p tag=%s off=%zu\n",
            (unsigned)tid, ip, (void*)a, snap.tag.c_str(), off);
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
    const char* func, const char* file, int line)
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

    // ενημέρωση region map
    /*PIN_GetLock(&g_regions_lock, tid);
    Region r;
    r.start = (ADDRINT)ptr;
    r.size  = size;
    r.tag   = tag;
    r.freed = false;
    g_regions[r.start] = r;
    PIN_ReleaseLock(&g_regions_lock);*/

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
            "overlap_start=%p overlap_size=%zu overlap_tag=%s site=%s:%d (%s)\n",
            (unsigned)tid,
            (void*)r.start, r.size, r.tag.c_str(),
            (void*)ov.start, ov.size, ov.tag.c_str(),
            file ? file : "?", line, func ? func : "?");
        fflush(tracef);
    }

    if (eventsf) {
        fprintf(eventsf,
            "ANOMALY alloc_overlap new_start=%p new_size=%zu new_tag=%s "
            "overlap_start=%p overlap_size=%zu overlap_tag=%s site=%s:%d (%s)\n",
            (void*)r.start, r.size, r.tag.c_str(),
            (void*)ov.start, ov.size, ov.tag.c_str(),
            file ? file : "?", line, func ? func : "?");
        fflush(eventsf);
    }

    if (logf) {
        fprintf(logf,
            "[ANOMALY] alloc_overlap new_start=%p new_size=%zu new_tag=%s "
            "overlap_start=%p overlap_size=%zu overlap_tag=%s @%s:%d (%s)\n",
            (void*)r.start, r.size, r.tag.c_str(),
            (void*)ov.start, ov.size, ov.tag.c_str(),
            file ? file : "?", line, func ? func : "?");
        fflush(logf);
    }

    PIN_ReleaseLock(&g_events_lock);
    return; // ΣΗΜΑΝΤΙΚΟ
}

    // Γράψιμο σε trace + events + log με κοινό lock
    PIN_GetLock(&g_events_lock, tid);

    if (tracef) {
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=%s site=%s:%d (%s)\n",
                (unsigned)tid,
                (void*)r.start, r.size, r.tag.c_str(),
                file ? file : "?", line, func ? func : "?");
        fflush(tracef);
    }

    if (logf) {
        fprintf(logf, "[HOOK ALLOC] p=%p size=%zu tag=%s @%s:%d (%s)\n",
                ptr, size, tag, file ? file : "?", line, func ? func : "?");
        fflush(logf);
    }
    if (eventsf) {
        fprintf(eventsf, "alloc start=%p size=%zu tag=%s site=%s:%d (%s)\n",
                (void*)r.start, r.size, r.tag.c_str(),
                file ? file : "?", line, func ? func : "?");
        fflush(eventsf);
    }

    PIN_ReleaseLock(&g_events_lock);
}


static VOID CallFreeSite(VOID* ptr, const char* type_tag,
    const char* func, const char* file, int line)
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
    /*auto it = g_regions.find((ADDRINT)ptr);
    if (it != g_regions.end()) {
        it->second.freed = true;
        snap  = it->second;
        known = true;
    }*/

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
                    "T%u free  start=%p size=%zu tag=%s site=%s:%d (%s)\n",
                    (unsigned)tid,
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    file ? file : "?", line, func ? func : "?");
        } else {
            fprintf(tracef,
                    "T%u free  start=%p tag=%s site=%s:%d (%s) UNKNOWN_REGION\n",
                    (unsigned)tid,
                    ptr, tag,
                    file ? file : "?", line, func ? func : "?");
        }
        fflush(tracef);
    }

    if (logf) {
        fprintf(logf, "[HOOK FREE ] p=%p tag=%s @%s:%d (%s)%s\n",
                ptr, tag,
                file ? file : "?", line, func ? func : "?",
                known ? "" : " (UNKNOWN)");
        fflush(logf);
    }
    if (eventsf) {
        if (known) {
            fprintf(eventsf, "free  start=%p size=%zu tag=%s site=%s:%d (%s)\n",
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    file ? file : "?", line, func ? func : "?");
        } else {
            fprintf(eventsf, "free  start=%p tag=%s site=%s:%d (%s)\n",
                    ptr, tag,
                    file ? file : "?", line, func ? func : "?");
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
    int line)
{
    ThreadCtx* tc = CTX(tid);
    if (!tc) return;

    tc->hasPendingAlloc  = true;
    tc->pendingSize      = size;
    tc->pendingTypeTag   = type_tag;
    tc->pendingFunc      = func;
    tc->pendingFile      = file;
    tc->pendingLine      = line;
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
                  tc->pendingLine);

    tc->hasPendingAlloc = false; // cleanup
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
static VOID AfterMalloc(ADDRINT ret, size_t sz) {
    if (!ret || sz == 0) return;
    THREADID tid = PIN_ThreadId();

    PIN_GetLock(&g_regions_lock, tid);
    Region r; r.start = ret; r.size = sz; r.tag = "heap"; //r.freed = false;
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);
    if (eventsf) {
        fprintf(eventsf, "alloc start=%p size=%zu tag=heap site=libc:malloc\n", (void*)ret, sz);
        fflush(eventsf);
    }
    if (tracef) {
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=heap site=libc:malloc\n",
                (unsigned)tid, (void*)ret, sz);
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}

static VOID AfterCalloc(ADDRINT ret, size_t n, size_t sz) {
    if (!ret || n==0 || sz==0) return;
    const size_t bytes = n*sz;
    THREADID tid = PIN_ThreadId();

    PIN_GetLock(&g_regions_lock, tid);
    Region r; r.start = ret; r.size = bytes; r.tag = "heap:calloc"; //r.freed = false;
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);
    if (eventsf) {
        fprintf(eventsf, "alloc start=%p size=%zu tag=heap:calloc site=libc:calloc\n",
                (void*)ret, bytes);
        fflush(eventsf);
    }
    if (tracef) {
        fprintf(tracef,
                "T%u alloc start=%p size=%zu tag=heap:calloc site=libc:calloc\n",
                (unsigned)tid, (void*)ret, bytes);
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}

static VOID AfterRealloc(ADDRINT ret, ADDRINT oldp, size_t sz) {
    THREADID tid = PIN_ThreadId();

    if (oldp) {
        PIN_GetLock(&g_regions_lock, tid);
        //auto it = g_regions.find(oldp);
        //if (it != g_regions.end()) it->second.freed = true;
        auto it = g_regions.find(oldp);
        if (it != g_regions.end()) g_regions.erase(it);
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (eventsf) {
            fprintf(eventsf, "free  start=%p tag=heap site=libc:realloc(old)\n", (void*)oldp);
            fflush(eventsf);
        }
        if (tracef) {
            fprintf(tracef,
                    "T%u free  start=%p tag=heap site=libc:realloc(old)\n",
                    (unsigned)tid, (void*)oldp);
            fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
    if (ret && sz) {
        PIN_GetLock(&g_regions_lock, tid);
        Region r; r.start = ret; r.size = sz; r.tag = "heap:realloc"; //r.freed = false;
        g_regions[ret] = r;
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, tid);
        if (eventsf) {
            fprintf(eventsf, "alloc start=%p size=%zu tag=heap:realloc site=libc:realloc\n",
                    (void*)ret, sz);
            fflush(eventsf);
        }
        if (tracef) {
            fprintf(tracef,
                    "T%u alloc start=%p size=%zu tag=heap:realloc site=libc:realloc\n",
                    (unsigned)tid, (void*)ret, sz);
            fflush(tracef);
        }
        PIN_ReleaseLock(&g_events_lock);
    }
}

static VOID BeforeFree(ADDRINT p) {
    if (!p) return;
    THREADID tid = PIN_ThreadId();
    bool known=false; Region snap;

    PIN_GetLock(&g_regions_lock, tid);
    //auto it = g_regions.find(p);
    //if (it != g_regions.end()) { it->second.freed = true; snap = it->second; known=true; }
    auto it = g_regions.find(p);
    if (it != g_regions.end()) { snap = it->second; known=true; g_regions.erase(it); }
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, tid);
    if (eventsf) {
        if (known) fprintf(eventsf, "free  start=%p size=%zu tag=%s site=libc:free\n",
                           (void*)snap.start, snap.size, snap.tag.c_str());
        else       fprintf(eventsf, "free  start=%p tag=? site=libc:free\n", (void*)p);
        fflush(eventsf);
    }
    if (tracef) {
        if (known) {
            fprintf(tracef,
                    "T%u free  start=%p size=%zu tag=%s site=libc:free\n",
                    (unsigned)tid,
                    (void*)snap.start, snap.size, snap.tag.c_str());
        } else {
            fprintf(tracef,
                    "T%u free  start=%p tag=? site=libc:free\n",
                    (unsigned)tid, (void*)p);
        }
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_events_lock);
}


//enimerwnoume ta malloc/calloc/realloc/free tis libc an to knob einai energopoihmeno.
static VOID HookLibcAllocators(IMG img) {
    if (!KnobUseLibcHooks.Value()) return;
    if (IMG_Type(img) != IMG_TYPE_SHAREDLIB) return; // typically libc is shared

    RTN r;

    r = RTN_FindByName(img, "malloc");
    if (RTN_Valid(r)) {
        RTN_Open(r);
        PROTO p = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT, "malloc",
            PIN_PARG(size_t), PIN_PARG_END());
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterMalloc),
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        PROTO_Free(p);
        RTN_Close(r);
        PIN_GetLock(&g_events_lock, 0);
        if (logf) { fprintf(logf, "[HOOK] libc malloc in %s\n", IMG_Name(img).c_str()); fflush(logf); }
        PIN_ReleaseLock(&g_events_lock);
    }

    r = RTN_FindByName(img, "calloc");
    if (RTN_Valid(r)) {
        RTN_Open(r);
        PROTO p = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT, "calloc",
            PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterCalloc),
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        PROTO_Free(p);
        RTN_Close(r);
        PIN_GetLock(&g_events_lock, 0);
        if (logf) { fprintf(logf, "[HOOK] libc calloc in %s\n", IMG_Name(img).c_str()); fflush(logf); }
        PIN_ReleaseLock(&g_events_lock);
    }

    r = RTN_FindByName(img, "realloc");
    if (RTN_Valid(r)) {
        RTN_Open(r);
        PROTO p = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT, "realloc",
            PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG_END());
        RTN_InsertCall(r, IPOINT_AFTER, AFUNPTR(AfterRealloc),
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // old ptr
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        PROTO_Free(p);
        RTN_Close(r);
        PIN_GetLock(&g_events_lock, PIN_ThreadId());
        if (logf) { fprintf(logf, "[HOOK] libc realloc in %s\n", IMG_Name(img).c_str()); fflush(logf); }
        PIN_ReleaseLock(&g_events_lock);
    }

    r = RTN_FindByName(img, "free");
    if (RTN_Valid(r)) {
        RTN_Open(r);
        PROTO p = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT, "free",
            PIN_PARG(void*), PIN_PARG_END());
        RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(BeforeFree),
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        PROTO_Free(p);
        RTN_Close(r);
        PIN_GetLock(&g_events_lock, PIN_ThreadId());
        if (logf) { fprintf(logf, "[HOOK] libc free in %s\n", IMG_Name(img).c_str()); fflush(logf); }
        PIN_ReleaseLock(&g_events_lock);
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

    g_tls_key = PIN_CreateThreadDataKey(nullptr);

    // Global files
    logf    = fopen("pintool.log", "w");
    eventsf = fopen("pinatrace.events", "w");  // κρατάμε το events όπως πριν
    tracef  = fopen("pinatrace.out", "w");     // ΕΝΙΑΙΟ trace file

    // Callbacks
    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    PIN_StartProgram(); // never returns
    return 0;
}