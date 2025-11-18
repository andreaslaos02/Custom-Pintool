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
    bool    freed;
    Region() : start(0), size(0), tag("-"), freed(false) {}
};

// Global region map (keyed by start)
static std::map<ADDRINT, Region> g_regions;     //taksinomimeno map kata start

// Locks
static PIN_LOCK g_regions_lock;  // protects g_regions
static PIN_LOCK g_events_lock;   // protects events/log global files

// -------------------------- Output files -------------------------
static FILE* logf    = nullptr;          // pintool.log (hooks summary)
static FILE* eventsf = nullptr;          // pinatrace.events (alloc/free only)

// Thread-local context: per-thread trace file - apothikevonde ta load/store gia kathe thread
struct ThreadCtx {
    FILE* out = nullptr;  // pinatrace.<pid>.<tid>.out
};
static TLS_KEY g_tls_key;

// Helper: fetch per-thread ctx
static inline ThreadCtx* CTX(THREADID tid) {
    return static_cast<ThreadCtx*>(PIN_GetThreadData(g_tls_key, tid));
}

// ------------------------- Lookup helper -------------------------
// Snapshot variant: γεμίζει το out και επιστρέφει true/false.
// Το snapshot αποφεύγει να κρατάμε pointer σε δεδομένα του map μετά το unlock για να αποφευγετε η αλλαγη του μετα.
// Τa records doulevoun me stathera dedomena.
static bool FindRegion(ADDRINT a, Region &out) {
    bool found = false;
    PIN_GetLock(&g_regions_lock, PIN_ThreadId());
    auto it = g_regions.upper_bound(a);  // first start > a
    if (it != g_regions.begin()) {
        --it;                            // candidate: start <= a
        const Region &r = it->second;
        if (a >= r.start && a < (r.start + r.size)) {
            out = r;                     // snapshot (αντιγράφει και το string)
            found = true;
        }
    }
    PIN_ReleaseLock(&g_regions_lock);
    return found;
}

// --------------------- Record memory accesses --------------------
static VOID RecordRead(THREADID tid, VOID* ip, VOID* ea) {
    ThreadCtx* tc = CTX(tid);       //pernei to arxeio tou thread.
    if (!tc || !tc->out) return; // TLS not ready yet / no file

    const ADDRINT a = (ADDRINT)ea;
    Region snap;
    if (!FindRegion(a, snap)) return;

    const size_t off = (size_t)(a - snap.start);
    if (off >= snap.size) return; // extra guard gia to case pou allakse to region meta to unlock.

    // per-thread file: δεν κρατάμε global lock εδώ
    // (fprintf μπορεί να καλέσει libc, αλλά δεν κάνουμε hook libc by default)
    fprintf(tc->out, "%p: load  %p tag=%s off=%zu\n",
            ip, (void*)a, snap.tag.c_str(), off);
}

static VOID RecordWrite(THREADID tid, VOID* ip, VOID* ea) {
    ThreadCtx* tc = CTX(tid);
    if (!tc || !tc->out) return;

    const ADDRINT a = (ADDRINT)ea;
    Region snap;
    if (!FindRegion(a, snap)) return;

    const size_t off = (size_t)(a - snap.start);
    if (off >= snap.size) return;

    fprintf(tc->out, "%p: store %p tag=%s off=%zu\n",
            ip, (void*)a, snap.tag.c_str(), off);
}

// ---------------- Instruction instrumentation --------------------
// callbacks gia kathe entoli me mnhmh prin ektelesti kai mono otan ektelestei pragrmatika mnhmh (predicated)
static VOID Instruction(INS ins, VOID*) {
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

static VOID CallAllocSite(CONTEXT*, AFUNPTR,
                          VOID* ptr, size_t size, const char* type_tag,
                          const char* func, const char* file, int line) {
    if (!ptr || size == 0) return;
    const char* tag = type_tag ? type_tag : "?";

    // ενημέρωση regions (με lock)
    PIN_GetLock(&g_regions_lock, PIN_ThreadId());       //lock se athe enimerwsi tou map
    Region r;
    r.start = (ADDRINT)ptr;
    r.size  = size;
    r.tag   = tag;
    r.freed = false;
    g_regions[r.start] = r;
    PIN_ReleaseLock(&g_regions_lock);

    // Log + Events (single global files)
    PIN_GetLock(&g_events_lock, PIN_ThreadId());    //lock se athe enimerwsi twn arxeiwn
    if (logf) {
        fprintf(logf, "[HOOK ALLOC] p=%p size=%zu tag=%s @%s:%d (%s)\n",
                ptr, size, tag, file?file:"?", line, func?func:"?");
        fflush(logf);
    }
    if (eventsf) {
        fprintf(eventsf, "alloc start=%p size=%zu tag=%s site=%s:%d (%s)\n",
                (void*)r.start, r.size, r.tag.c_str(),
                file?file:"?", line, func?func:"?");
        fflush(eventsf);
    }
    PIN_ReleaseLock(&g_events_lock);
}

static VOID CallFreeSite(CONTEXT*, AFUNPTR,
                         VOID* ptr, const char* type_tag,
                         const char* func, const char* file, int line) {
    if (!ptr) return;
    const char* tag = type_tag ? type_tag : "?";

    bool known = false;
    Region snap;

    PIN_GetLock(&g_regions_lock, PIN_ThreadId());
    auto it = g_regions.find((ADDRINT)ptr);
    if (it != g_regions.end()) {
        it->second.freed = true; // oxi diagrafi gia UAF detection
        snap = it->second;
        known = true;
    }
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, PIN_ThreadId());
    if (logf) {
        fprintf(logf, "[HOOK FREE ] p=%p tag=%s @%s:%d (%s)%s\n",
                ptr, tag, file?file:"?", line, func?func:"?", known?"":" (UNKNOWN)");
        fflush(logf);
    }
    if (eventsf) {
        if (known) {
            fprintf(eventsf, "free  start=%p size=%zu tag=%s site=%s:%d (%s)\n",
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    file?file:"?", line, func?func:"?");
        } else {
            fprintf(eventsf, "free  start=%p tag=%s site=%s:%d (%s)\n",
                    ptr, tag, file?file:"?", line, func?func:"?");
        }
        fflush(eventsf);
    }
    PIN_ReleaseLock(&g_events_lock);
}

// ----------------- Hook your dummy symbols if present ------------
// Vriskoume ta __memtrace_alloc_site kai __memtrace_free_site an yparxoun kai kanoume replace me ta dika mas (callAlloc/FreeSite).
// Scanarei to image gia ta dummy sites.
static VOID HookDummySites(IMG img) {
    for (SEC s = IMG_SecHead(img); SEC_Valid(s); s = SEC_Next(s)) {
        for (RTN r = SEC_RtnHead(s); RTN_Valid(r); r = RTN_Next(r)) {
            string n = RTN_Name(r);

            if (n.find("__memtrace_alloc_site") != string::npos) {
                PROTO p = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT, n.c_str(),
                    PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG(const char*),
                    PIN_PARG(const char*), PIN_PARG(const char*), PIN_PARG(int), PIN_PARG_END());

                RTN_ReplaceSignature(
                    r, AFUNPTR(CallAllocSite),
                    IARG_PROTOTYPE, p, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                    IARG_END);
                PROTO_Free(p);

                PIN_GetLock(&g_events_lock, 0);
                if (logf) { fprintf(logf, "[HOOK] __memtrace_alloc_site in %s\n", IMG_Name(img).c_str()); fflush(logf); }
                PIN_ReleaseLock(&g_events_lock);
            }
            else if (n.find("__memtrace_free_site") != string::npos) {
                PROTO p = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT, n.c_str(),
                    PIN_PARG(void*), PIN_PARG(const char*),
                    PIN_PARG(const char*), PIN_PARG(const char*), PIN_PARG(int), PIN_PARG_END());

                RTN_ReplaceSignature(
                    r, AFUNPTR(CallFreeSite),
                    IARG_PROTOTYPE, p, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                    IARG_END);
                PROTO_Free(p);

                PIN_GetLock(&g_events_lock, 0);
                if (logf) { fprintf(logf, "[HOOK] __memtrace_free_site in %s\n", IMG_Name(img).c_str()); fflush(logf); }
                PIN_ReleaseLock(&g_events_lock);
            }
        }
    }
}

// ----------------- Optional glibc malloc/free hooks --------------
// otan energopoihthei to knob use_libc_hooks, kanoume hook ta malloc/calloc/realloc/free
// gia na parakolouthisoume kai auta ta allocations.
// Ta allocations apo libc exoun tag "heap", "heap:calloc", "heap:realloc" antistoixa.
// gia na enimerwnete to pinatrace.events arxeio gia ta alloc/free gegonota.
// se kathe malloc/calloc/realloc/free, enhmerwnoume to g_regions map antistoixa me size, freed=true, start kai tag.
static VOID AfterMalloc(ADDRINT ret, size_t sz) {
    if (!ret || sz == 0) return;
    PIN_GetLock(&g_regions_lock, PIN_ThreadId());
    Region r; r.start = ret; r.size = sz; r.tag = "heap"; r.freed = false;
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, PIN_ThreadId());
    if (eventsf) { fprintf(eventsf, "alloc start=%p size=%zu tag=heap site=libc:malloc\n", (void*)ret, sz); fflush(eventsf); }
    PIN_ReleaseLock(&g_events_lock);
}
static VOID AfterCalloc(ADDRINT ret, size_t n, size_t sz) {
    if (!ret || n==0 || sz==0) return;
    const size_t bytes = n*sz;
    PIN_GetLock(&g_regions_lock, PIN_ThreadId());
    Region r; r.start = ret; r.size = bytes; r.tag = "heap:calloc"; r.freed = false;
    g_regions[ret] = r;
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, PIN_ThreadId());
    if (eventsf) { fprintf(eventsf, "alloc start=%p size=%zu tag=heap:calloc site=libc:calloc\n", (void*)ret, bytes); fflush(eventsf); }
    PIN_ReleaseLock(&g_events_lock);
}
static VOID AfterRealloc(ADDRINT ret, ADDRINT oldp, size_t sz) {
    if (oldp) {
        PIN_GetLock(&g_regions_lock, PIN_ThreadId());
        auto it = g_regions.find(oldp);
        if (it != g_regions.end()) it->second.freed = true;
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, PIN_ThreadId());
        if (eventsf) { fprintf(eventsf, "free  start=%p tag=heap site=libc:realloc(old)\n", (void*)oldp); fflush(eventsf); }
        PIN_ReleaseLock(&g_events_lock);
    }
    if (ret && sz) {
        PIN_GetLock(&g_regions_lock, PIN_ThreadId());
        Region r; r.start = ret; r.size = sz; r.tag = "heap:realloc"; r.freed = false;
        g_regions[ret] = r;
        PIN_ReleaseLock(&g_regions_lock);

        PIN_GetLock(&g_events_lock, PIN_ThreadId());
        if (eventsf) { fprintf(eventsf, "alloc start=%p size=%zu tag=heap:realloc site=libc:realloc\n", (void*)ret, sz); fflush(eventsf); }
        PIN_ReleaseLock(&g_events_lock);
    }
}
static VOID BeforeFree(ADDRINT p) {
    if (!p) return;
    bool known=false; Region snap;
    PIN_GetLock(&g_regions_lock, PIN_ThreadId());
    auto it = g_regions.find(p);
    if (it != g_regions.end()) { it->second.freed = true; snap = it->second; known=true; }
    PIN_ReleaseLock(&g_regions_lock);

    PIN_GetLock(&g_events_lock, PIN_ThreadId());
    if (eventsf) {
        if (known) fprintf(eventsf, "free  start=%p size=%zu tag=%s site=libc:free\n",
                           (void*)snap.start, snap.size, snap.tag.c_str());
        else       fprintf(eventsf, "free  start=%p tag=? site=libc:free\n", (void*)p);
        fflush(eventsf);
    }
    PIN_ReleaseLock(&g_events_lock);
}


//enimerwnoume ta malloc/calloc/realloc/free tis libc an to knob einai energopoihmeno.
//katagrafei sto pintool.log to hooking kathe function.
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
// kathe thread dimiourgei to diko tou arxeio trace.
// ta arxeia einai pinatrace.<pid>.<tid>.out
static VOID ThreadStart(THREADID tid, CONTEXT*, INT32, VOID*) {
    int pid = getpid();
    char path[256];
    snprintf(path, sizeof(path), "pinatrace.%d.%u.out", pid, (unsigned)tid);

    ThreadCtx* tc = new ThreadCtx();
    tc->out = fopen(path, "w");
    if (tc->out) {
        setvbuf(tc->out, nullptr, _IOFBF, 1<<20); // 1MB buffer
    }
    PIN_SetThreadData(g_tls_key, tc, tid);
}

// kathe thread kleinei to diko tou arxeio trace.
// apodesmevei to thread-local context.
// grafei "#eof" sto telos tou arxeiou.
static VOID ThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*) {
    ThreadCtx* tc = CTX(tid);
    if (tc) {
        if (tc->out) { fprintf(tc->out, "#eof\n"); fclose(tc->out); }
        delete tc;
        PIN_SetThreadData(g_tls_key, nullptr, tid);
    }
}

// ----------------------------- Fini ------------------------------
// Global fini: κλείνει τα global αρχεία log/events
// και γράφει "#eof" στο events αρχείο.
static VOID Fini(INT32, VOID*) {
    if (eventsf) { fprintf(eventsf, "#eof\n"); fclose(eventsf); }
    if (logf)    fclose(logf);
}

// ------------------------------ main -----------------------------
// dilwnei ta call backs kai arxizei to Pin.
int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;

    PIN_InitLock(&g_regions_lock);
    PIN_InitLock(&g_events_lock);

    g_tls_key = PIN_CreateThreadDataKey(nullptr);

    // Global files (όχι per-thread)
    logf    = fopen("pintool.log", "w");
    eventsf = fopen("pinatrace.events", "w");

    // Callbacks
    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    PIN_StartProgram(); // never returns
    return 0;
}