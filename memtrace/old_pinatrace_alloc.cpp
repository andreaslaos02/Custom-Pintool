// pinatrace_alloc.cpp  — trace R/W και labeling από dummy alloc sites
#include "pin.H"
#include <map>
#include <string>
#include <cstdio>
#include <stdio.h>

using std::string;

// ---- Region map: start -> {start,size,tag}
struct Region { ADDRINT start; size_t size; string tag; };
static std::map<ADDRINT, Region> g_regions;

// ---- outputs
static FILE* tracef = nullptr; // pinatrace.out (R/W + tag)
static FILE* logf   = nullptr; // pintool.log   (HOOK/ALLOC/FREE)

// ---- helpers
static const char* FindTag(ADDRINT a)
{
    auto it = g_regions.upper_bound(a);
    if (it == g_regions.begin()) return "-";
    --it;
    const Region& r = it->second;
    if (a >= r.start && a < r.start + r.size) return r.tag.c_str();
    return "-";
}

// ---- record memory accesses
static VOID RecordRead(VOID* ip, VOID* addr)
{
    const char* t = FindTag((ADDRINT)addr);
    //if (t && t[0] != '-')  // γράψε μόνο αν υπάρχει label
    fprintf(tracef, "%p: R %p %s\n", ip, addr, t);
}

static VOID RecordWrite(VOID* ip, VOID* addr)
{
    const char* t = FindTag((ADDRINT)addr);
    //if (t && t[0] != '-')  // γράψε μόνο αν υπάρχει label
    fprintf(tracef, "%p: W %p %s\n", ip, addr, t);
}

static VOID Instruction(INS ins, VOID*)
{
    const UINT32 n = INS_MemoryOperandCount(ins);
    for (UINT32 i = 0; i < n; ++i) {
        if (INS_MemoryOperandIsRead(ins, i)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(RecordRead),
                                     IARG_INST_PTR, IARG_MEMORYOP_EA, i, IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, i)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(RecordWrite),
                                     IARG_INST_PTR, IARG_MEMORYOP_EA, i, IARG_END);
        }
    }
}

// ---- dummy-site wrappers (θα αντικαταστήσουν τις __memtrace_* )
static VOID CallAllocSite(CONTEXT* ctxt, AFUNPTR orig,
                          VOID* ptr, size_t size, const char* type_tag,
                          const char* func, const char* file, int line)
{
    // εκτέλεσε ΠΡΩΤΑ την πραγματική dummy συνάρτηση (ώστε να τυπώσει αν θέλεις)
    /*PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
        CALLINGSTD_DEFAULT, orig, nullptr,
        PIN_PARG(void*), ptr, 
        PIN_PARG(size_t), size,
        PIN_PARG(const char*), type_tag, 
        PIN_PARG(const char*), func,
        PIN_PARG(const char*), file, 
        PIN_PARG(int), line, 
        PIN_PARG_END());*/

    if (ptr && size) {
        g_regions[(ADDRINT)ptr] = { (ADDRINT)ptr, size, type_tag ? type_tag : "?" };
        if (logf) fprintf(logf, "[ALLOC] p=%p size=%zu tag=%s @%s:%d (%s)\n",
                          ptr, size, type_tag ? type_tag : "?",
                          file ? file : "?", line, func ? func : "?");
    }
}

static VOID CallFreeSite(CONTEXT* ctxt, AFUNPTR orig,
                         VOID* ptr, const char* type_tag,
                         const char* func, const char* file, int line)
{
    /*PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
        CALLINGSTD_DEFAULT, orig, nullptr,
        PIN_PARG(void*), ptr, 
        PIN_PARG(const char*), type_tag,
        PIN_PARG(const char*), func, 
        PIN_PARG(const char*), file,
        PIN_PARG(int), line, 
        PIN_PARG_END());*/

    if (ptr) {
        g_regions.erase((ADDRINT)ptr); // απλό: κλειδί = start ptr που πήραμε
        if (logf) fprintf(logf, "[FREE ] p=%p tag=%s @%s:%d (%s)\n",
                          ptr, type_tag ? type_tag : "?",
                          file ? file : "?", line, func ? func : "?");
    }
}

// ---- hook σε __memtrace_alloc_site / __memtrace_free_site
static VOID ImageLoad(IMG img, VOID*)
{
    for (SEC s = IMG_SecHead(img); SEC_Valid(s); s = SEC_Next(s)) {
        for (RTN r = SEC_RtnHead(s); RTN_Valid(r); r = RTN_Next(r)) {
            string n = RTN_Name(r);

            if (n.find("__memtrace_alloc_site") != string::npos) {
                PROTO p = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT, n.c_str(),
                    PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG(const char*),
                    PIN_PARG(const char*), PIN_PARG(const char*), PIN_PARG(int), PIN_PARG_END());

                RTN_ReplaceSignature(r, AFUNPTR(CallAllocSite),
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
                    PIN_PARG(const char*), PIN_PARG(const char*), PIN_PARG(int), PIN_PARG_END());

                RTN_ReplaceSignature(r, AFUNPTR(CallFreeSite),
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

    tracef = fopen("pinatrace.out", "w");
    logf   = fopen("pintool.log",  "w");

    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram(); // JIT mode
    return 0;
}