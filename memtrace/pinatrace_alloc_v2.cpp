/* g++ -Wall -Werror -Wno-unknown-pragmas -DPIN_CRT=1 -fno-stack-protector -fno-exceptions     -funwind-tables -fasynchronous-unwind-tables -fno-rtti -DTARGET_IA32E -DHOST_IA32E     -fPIC -DTARGET_LINUX -fabi-version=2 -faligned-new     -I"$PIN_ROOT/source/include/pin" -I"$PIN_ROOT/source/include/pin/gen"     -isystem "$PIN_ROOT/extras/cxx/include" -isystem "$PIN_ROOT/extras/crt/include"     -isystem "$PIN_ROOT/extras/crt/include/arch-x86_64"     -isystem "$PIN_ROOT/extras/crt/include/kernel/uapi"     -isystem "$PIN_ROOT/extras/crt/include/kernel/uapi/asm-x86"     -I"$PIN_ROOT/extras/components/include"     -I"$PIN_ROOT/extras/xed-intel64/include/xed"     -I"$PIN_ROOT/source/tools/Utils" -I"$PIN_ROOT/source/tools/InstLib"     -O3 -fomit-frame-pointer -fno-strict-aliasing -Wno-dangling-pointer     -c -o obj-intel64/pinatrace_alloc_v2.o pinatrace_alloc_v2.cpp*/
/* g++ -shared -Wl,--hash-style=sysv     "$PIN_ROOT/intel64/runtime/pincrt/crtbeginS.o" -Wl,-Bsymbolic     -Wl,--version-script="$PIN_ROOT/source/include/pin/pintool.ver" -fabi-version=2     -o obj-intel64/pinatrace_alloc_v2.so obj-intel64/pinatrace_alloc_v2.o     -L"$PIN_ROOT/intel64/runtime/pincrt" -L"$PIN_ROOT/intel64/lib"     -L"$PIN_ROOT/intel64/lib-ext" -L"$PIN_ROOT/extras/xed-intel64/lib"     -lpin -lxed "$PIN_ROOT/intel64/runtime/pincrt/crtendS.o"     -lpindwarf -ldwarf -ldl-dynamic -nostdlib -lc++ -lc++abi -lm-dynamic -lc-dynamic -lunwind-dynamic */
/* "$PIN_ROOT/pin" -t ./obj-intel64/pinatrace_alloc_v2.so -- ./ds_demo */
// pinatrace_alloc.cpp — trace load/store + alloc/free με labeling από dummy alloc sites
#include "pin.H"
#include <map>
#include <string>
#include <cstdio>
#include <cstdint>

using std::string;

// ---------- Region map: start -> Region ----------
struct Region {
    ADDRINT start;
    size_t  size;
    string  tag;
    bool    freed;
    Region() : start(0), size(0), tag("-"), freed(false) {}
};

static std::map<ADDRINT, Region> g_regions; // keyed by start

// ---------- outputs ----------
static FILE* tracef = nullptr; // pinatrace.out (loads/stores + alloc/free)
static FILE* logf   = nullptr; // pintool.log   (HOOK/ALLOC/FREE)

// ---------- threading lock ----------
static PIN_LOCK g_lock;

// ---------- lookup helper ----------
static const Region* FindRegion(ADDRINT a)
{
    auto it = g_regions.upper_bound(a);   // πρώτο start > a
    if (it == g_regions.begin()) return nullptr;
    --it;                                 // start <= a
    const Region& r = it->second;
    if (a >= r.start && a < (r.start + r.size)) return &r;
    return nullptr;
}

// ---------- record memory accesses (ΜΟΝΟ load/store) ----------
static VOID RecordRead(VOID* ip, VOID* ea)
{
    const ADDRINT a = (ADDRINT)ea;
    PIN_GetLock(&g_lock, PIN_ThreadId());
    const Region* r = FindRegion(a);
    if (r) {
        const size_t off = (size_t)(a - r->start);
        // Καθαρή γραμμή load: ΧΩΡΙΣ size/state
        fprintf(tracef, "%p: load  %p tag=%s off=%zu\n",
                ip, (void*)a, r->tag.c_str(), off);
    }
    PIN_ReleaseLock(&g_lock);
}

static VOID RecordWrite(VOID* ip, VOID* ea)
{
    const ADDRINT a = (ADDRINT)ea;
    PIN_GetLock(&g_lock, PIN_ThreadId());
    const Region* r = FindRegion(a);
    if (r) {
        const size_t off = (size_t)(a - r->start);
        // Καθαρή γραμμή store: ΧΩΡΙΣ size/state
        fprintf(tracef, "%p: store %p tag=%s off=%zu\n",
                ip, (void*)a, r->tag.c_str(), off);
    }
    PIN_ReleaseLock(&g_lock);
}

// ---------- instruction instrumentation ----------
static VOID Instruction(INS ins, VOID*)
{
    const UINT32 n = INS_MemoryOperandCount(ins);
    for (UINT32 i = 0; i < n; ++i) {
        if (INS_MemoryOperandIsRead(ins, i)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(RecordRead),
                IARG_INST_PTR, IARG_MEMORYOP_EA, i, IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, i)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(RecordWrite),
                IARG_INST_PTR, IARG_MEMORYOP_EA, i, IARG_END);
        }
    }
}

// ---------- dummy-site wrappers (αντικαθιστούν __memtrace_* ) ----------
static VOID CallAllocSite(CONTEXT* /*ctxt*/, AFUNPTR /*orig*/,
                          VOID* ptr, size_t size, const char* type_tag,
                          const char* func, const char* file, int line)
{
    if (!ptr || size == 0) return;

    const char* tag = type_tag ? type_tag : "?";

    PIN_GetLock(&g_lock, PIN_ThreadId());
    // ενημέρωσε/αντικατάστησε το region
    Region r;
    r.start = (ADDRINT)ptr;
    r.size  = size;
    r.tag   = tag;
    r.freed = false;
    g_regions[r.start] = r;

    // LOG (.log)
    if (logf) {
        fprintf(logf, "[ALLOC] p=%p size=%zu tag=%s @%s:%d (%s)\n",
                ptr, size, tag, file ? file : "?", line, func ? func : "?");
        fflush(logf);
    }

    // OUT (.out) — one-shot event γραμμή alloc
    if (tracef) {
        fprintf(tracef, "alloc start=%p size=%zu tag=%s site=%s:%d (%s)\n",
                (void*)r.start, r.size, r.tag.c_str(),
                file ? file : "?", line, func ? func : "?");
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_lock);
}

static VOID CallFreeSite(CONTEXT* /*ctxt*/, AFUNPTR /*orig*/,
                         VOID* ptr, const char* type_tag,
                         const char* func, const char* file, int line)
{
    if (!ptr) return;
    const char* tag = type_tag ? type_tag : "?";

    PIN_GetLock(&g_lock, PIN_ThreadId());
    bool known = false;
    Region snap;
    if (auto it = g_regions.find((ADDRINT)ptr); it != g_regions.end()) {
        it->second.freed = true; // κρατάμε status για UAF (δεν σβήνουμε)
        snap = it->second;
        known = true;
    }

    // LOG (.log)
    if (logf) {
        fprintf(logf, "[FREE ] p=%p tag=%s @%s:%d (%s)%s\n",
                ptr, tag, file ? file : "?", line, func ? func : "?", known ? "" : "  (UNKNOWN)");
        fflush(logf);
    }

    // OUT (.out) — one-shot event γραμμή free
    if (tracef) {
        if (known) {
            fprintf(tracef, "free  start=%p size=%zu tag=%s site=%s:%d (%s)\n",
                    (void*)snap.start, snap.size, snap.tag.c_str(),
                    file ? file : "?", line, func ? func : "?");
        } else {
            fprintf(tracef, "free  start=%p tag=%s site=%s:%d (%s)\n",
                    ptr, tag, file ? file : "?", line, func ? func : "?");
        }
        fflush(tracef);
    }
    PIN_ReleaseLock(&g_lock);
}

// ---------- hook σε __memtrace_alloc_site / __memtrace_free_site ----------
static VOID ImageLoad(IMG img, VOID*)
{
    for (SEC s = IMG_SecHead(img); SEC_Valid(s); s = SEC_Next(s)) {
        for (RTN r = SEC_RtnHead(s); RTN_Valid(r); r = RTN_Next(r)) {
            string n = RTN_Name(r);

            if (n.find("__memtrace_alloc_site") != string::npos) {
                PROTO p = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT, n.c_str(),
                    PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG(const char*),
                    PIN_PARG(const char*), PIN_PARG(const char*), PIN_PARG(int),
                    PIN_PARG_END());

                RTN_ReplaceSignature(
                    r, AFUNPTR(CallAllocSite),
                    IARG_PROTOTYPE, p, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ptr
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // size
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // type_tag
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // func
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // file
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // line
                    IARG_END);
                PROTO_Free(p);

                if (logf) fprintf(logf, "[HOOK] %s in %s\n", n.c_str(), IMG_Name(img).c_str());
            }
            else if (n.find("__memtrace_free_site") != string::npos) {
                PROTO p = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT, n.c_str(),
                    PIN_PARG(void*), PIN_PARG(const char*),
                    PIN_PARG(const char*), PIN_PARG(const char*), PIN_PARG(int),
                    PIN_PARG_END());

                RTN_ReplaceSignature(
                    r, AFUNPTR(CallFreeSite),
                    IARG_PROTOTYPE, p, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ptr
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // type_tag
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // func
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // file
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // line
                    IARG_END);
                PROTO_Free(p);

                if (logf) fprintf(logf, "[HOOK] %s in %s\n", n.c_str(), IMG_Name(img).c_str());
            }
        }
    }
}

static VOID Fini(INT32, VOID*)
{
    if (tracef) { fprintf(tracef, "#eof\n"); fclose(tracef); }
    if (logf)   fclose(logf);
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;

    PIN_InitLock(&g_lock);

    tracef = fopen("pinatrace.out", "w");
    logf   = fopen("pintool.log",  "w");

    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram(); // JIT mode — δεν επιστρέφει
    return 0;
}