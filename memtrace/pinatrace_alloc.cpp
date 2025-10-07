// pinatrace_alloc.cpp — trace R/W με labeling από dummy alloc sites
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
    bool    freed;   // true αν έχει γίνει free (UAF detection)
    Region() : start(0), size(0), tag("-"), freed(false) {}
};

static std::map<ADDRINT, Region> g_regions; // keyed by start

// ---------- outputs ----------
static FILE* tracef = nullptr; // pinatrace.out (R/W + tag + size + state)
static FILE* logf   = nullptr; // pintool.log   (HOOK/ALLOC/FREE)

// ---------- helpers ----------
static const Region* FindRegion(ADDRINT a)
{
    auto it = g_regions.upper_bound(a);   // πρώτο start > a
    if (it == g_regions.begin()) return nullptr;
    --it;                                 // start <= a
    const Region& r = it->second;
    if (a >= r.start && a < (r.start + r.size)) return &r;
    return nullptr;
}

// ---------- record memory accesses ----------
/*static VOID RecordRead(VOID* ip, VOID* addr)
{
    const Region* r = FindRegion((ADDRINT)addr);
    if (r) {
        fprintf(tracef, "%p: R %p %s size=%zu state=%s\n",
                ip, addr, r->tag.c_str(), r->size, r->freed ? "FREED" : "ALLOC");
    } else {
        fprintf(tracef, "%p: R %p -\n", ip, addr);
    }
}*/

// for printing only metadata recorded at allocation/free time
//  ---------- record memory accesses (filtered for known tags) ----------
static VOID RecordRead(VOID* ip, VOID* addr)
{
    const Region* r = FindRegion((ADDRINT)addr);
    if (!r) return; // αγνόησε αν δεν ανήκει σε καταγεγραμμένο region

    fprintf(tracef, "%p: R %p %s size=%zu state=%s\n",
            ip, addr, r->tag.c_str(), r->size, r->freed ? "FREED" : "ALLOC");
}

/*static VOID RecordWrite(VOID* ip, VOID* addr)
{
    const Region* r = FindRegion((ADDRINT)addr);
    if (r) {
        fprintf(tracef, "%p: W %p %s size=%zu state=%s\n",
                ip, addr, r->tag.c_str(), r->size, r->freed ? "FREED" : "ALLOC");
    } else {
        fprintf(tracef, "%p: W %p -\n", ip, addr);
    }
}*/

// for printing only metadata recorded at allocation/free time
// ---------- record memory accesses (filtered for known tags) ----------
static VOID RecordWrite(VOID* ip, VOID* addr)
{
    const Region* r = FindRegion((ADDRINT)addr);
    if (!r) return; // αγνόησε αν δεν ανήκει σε καταγεγραμμένο region

    fprintf(tracef, "%p: W %p %s size=%zu state=%s\n",
            ip, addr, r->tag.c_str(), r->size, r->freed ? "FREED" : "ALLOC");
}

static VOID Instruction(INS ins, VOID*) // trace R/W σε κάθε load/store
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
    // Δεν καλούμε το original dummy.
    if (ptr && size) {
        Region r;
        r.start = (ADDRINT)ptr;
        r.size  = size;
        r.tag   = type_tag ? type_tag : "?";
        r.freed = false;
        g_regions[r.start] = r;  // αντικατάσταση σε reuse
        if (logf) {
            fprintf(logf, "[ALLOC] p=%p size=%zu tag=%s @%s:%d (%s)\n",
                    ptr, size, r.tag.c_str(),
                    file ? file : "?", line, func ? func : "?");
        }
    }
}

static VOID CallFreeSite(CONTEXT* /*ctxt*/, AFUNPTR /*orig*/,
                         VOID* ptr, const char* type_tag,
                         const char* func, const char* file, int line)
{
    // Δεν καλούμε το original dummy.
    if (ptr) {
        auto it = g_regions.find((ADDRINT)ptr);
        if (it != g_regions.end()) {
            it->second.freed = true;      // κρατάμε το region για UAF detection
        }
        if (logf) {
            fprintf(logf, "[FREE ] p=%p tag=%s @%s:%d (%s)\n",
                    ptr, type_tag ? type_tag : "?",
                    file ? file : "?", line, func ? func : "?");
        }
    }
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
    PIN_InitSymbols();                // για ονόματα RTN/IMG
    if (PIN_Init(argc, argv)) return 1;

    tracef = fopen("pinatrace.out", "w");
    logf   = fopen("pintool.log",  "w");

    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram(); // JIT mode — δεν επιστρέφει
    return 0;
}