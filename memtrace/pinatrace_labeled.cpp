// pinatrace_labeled.cpp
// Labeled memory trace tool for PIN (ARRAY / LIST / UNKNOWN)
// Put in: $PIN_ROOT/source/tools/MyTools/pin_labeled/pinatrace_labeled.cpp

#include "pin.H"
#include <cstdio>
#include <map>
#include <string>
#include <cctype>

using std::string;

/* ===== Knobs ===== */
KNOB<UINT64> KnobArrayBytes(KNOB_MODE_WRITEONCE, "pintool", "array_bytes", "400000",
                            "bytes threshold to label a malloc region as ARRAY");
KNOB<UINT64> KnobListBytes (KNOB_MODE_WRITEONCE, "pintool", "list_bytes",  "16",
                            "bytes equal to a list node allocation to label as LIST");

/* ===== Label types and regions ===== */
enum Label : UINT8 { L_UNKNOWN = 0, L_ARRAY = 1, L_LIST = 2 };
static inline char LabelChar(Label L) { return (L == L_ARRAY) ? 'A' : (L == L_LIST) ? 'L' : '-'; }

struct Region {
    ADDRINT start;
    size_t  size;
    Label   label;
};

static std::map<ADDRINT, Region> g_regions;

/* ===== output file (trace) ===== */
static FILE* trace = nullptr;

/* ===== Helpers ===== */
static Label LabelOfAddr(ADDRINT a) {
    auto it = g_regions.upper_bound(a);
    if (it == g_regions.begin()) return L_UNKNOWN;
    --it;
    const Region& r = it->second;
    if (a >= r.start && a < r.start + r.size) return r.label;
    return L_UNKNOWN;
}

/* ===== Wrappers for malloc/calloc/realloc/free ===== */
static VOID* CallMalloc(CONTEXT* ctxt, AFUNPTR f, size_t sz) {
    VOID* ret = nullptr;
    PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT, f, nullptr,
                                PIN_PARG(void*), &ret,
                                PIN_PARG(size_t), sz,
                                PIN_PARG_END());

    Label L = L_UNKNOWN;
    if (sz >= KnobArrayBytes.Value()) L = L_ARRAY;
    if (sz == KnobListBytes.Value())  L = L_LIST;

    if (ret && L != L_UNKNOWN) {
        g_regions[(ADDRINT)ret] = Region{ (ADDRINT)ret, sz, L };
    }

    // debug
    fprintf(stderr, "[DEBUG] malloc(%zu) -> %p  label=%c\n", sz, ret, LabelChar(L));
    fflush(stderr);
    return ret;
}

static VOID* CallCalloc(CONTEXT* ctxt, AFUNPTR f, size_t n, size_t sz) {
    VOID* ret = nullptr;
    PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT, f, nullptr,
                                PIN_PARG(void*), &ret,
                                PIN_PARG(size_t), n,
                                PIN_PARG(size_t), sz,
                                PIN_PARG_END());

    size_t bytes = n * sz;
    Label L = L_UNKNOWN;
    if (bytes >= KnobArrayBytes.Value()) L = L_ARRAY;
    if (bytes == KnobListBytes.Value())  L = L_LIST;

    if (ret && L != L_UNKNOWN) {
        g_regions[(ADDRINT)ret] = Region{ (ADDRINT)ret, bytes, L };
    }

    // debug
    fprintf(stderr, "[DEBUG] calloc(%zu * %zu = %zu) -> %p  label=%c\n", n, sz, bytes, ret, LabelChar(L));
    fflush(stderr);
    return ret;
}

static VOID* CallRealloc(CONTEXT* ctxt, AFUNPTR f, VOID* p, size_t sz) {
    VOID* ret = nullptr;
    PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT, f, nullptr,
                                PIN_PARG(void*), &ret,
                                PIN_PARG(void*), p,
                                PIN_PARG(size_t), sz,
                                PIN_PARG_END());

    if (p) {
        auto it = g_regions.find((ADDRINT)p);
        if (it != g_regions.end()) g_regions.erase(it);
    }

    Label L = L_UNKNOWN;
    if (ret) {
        if (sz >= KnobArrayBytes.Value()) L = L_ARRAY;
        if (sz == KnobListBytes.Value())  L = L_LIST;
        if (L != L_UNKNOWN) {
            g_regions[(ADDRINT)ret] = Region{ (ADDRINT)ret, sz, L };
        }
    }

    // debug
    fprintf(stderr, "[DEBUG] realloc(%p, %zu) -> %p  label=%c\n", p, sz, ret, LabelChar(L));
    fflush(stderr);
    return ret;
}

static VOID CallFree(CONTEXT* ctxt, AFUNPTR f, VOID* p) {
    if (p) {
        auto it = g_regions.find((ADDRINT)p);
        if (it != g_regions.end()) g_regions.erase(it);
    }
    PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT, f, nullptr,
                                PIN_PARG(void), PIN_PARG(void*), p, PIN_PARG_END());
    // debug
    fprintf(stderr, "[DEBUG] free(%p)\n", p);
    fflush(stderr);
}

/* ===== Memory access logging (instrumentation) ===== */
static VOID RecordMemRead(VOID* ip, VOID* addr) {
    Label L = LabelOfAddr((ADDRINT)addr);
    fprintf(trace, "%p: R %p L=%c\n", ip, addr, LabelChar(L));
}
static VOID RecordMemRead2(VOID* ip, VOID* addr) {
    Label L = LabelOfAddr((ADDRINT)addr);
    fprintf(trace, "%p: R2 %p L=%c\n", ip, addr, LabelChar(L));
}
static VOID RecordMemWrite(VOID* ip, VOID* addr) {
    Label L = LabelOfAddr((ADDRINT)addr);
    fprintf(trace, "%p: W %p L=%c\n", ip, addr, LabelChar(L));
}

static VOID Instruction(INS ins, VOID* v) {
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                                     IARG_INST_PTR, IARG_MEMORYOP_EA, memOp, IARG_END);
        }
        if (INS_HasMemoryRead2(ins) && INS_MemoryOperandIsRead(ins, memOp)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead2,
                                     IARG_INST_PTR, IARG_MEMORYREAD2_EA, IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, memOp)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                                     IARG_INST_PTR, IARG_MEMORYOP_EA, memOp, IARG_END);
        }
    }
}

/* ===== ImageLoad: scan RTNs and hook allocator symbols (probed safe) ===== */
static VOID ImageLoad(IMG img, VOID*) {
    string imgName = IMG_Name(img);
    fprintf(stderr, "[IMG] %s\n", imgName.c_str());
    fflush(stderr);

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            string rname = RTN_Name(rtn);
            string lname = rname;
            for (char &c : lname) c = (char) tolower(c);

            // helper to try probed replacement (with arg indexes)
            auto try_hook = [&](const char* kind, PROTO proto, AFUNPTR repl,
                                INT32 a0 = -1, INT32 a1 = -1) {
                if (!RTN_IsSafeForProbedReplacement(rtn)) {
                    fprintf(stderr, "[MISS] %s not safe for probed replacement: %s in %s\n",
                            kind, rname.c_str(), imgName.c_str());
                    PROTO_Free(proto);
                    fflush(stderr);
                    return;
                }
                if (a0 == -1) {
                    RTN_ReplaceSignatureProbed(rtn, repl,
                                              IARG_PROTOTYPE, proto,
                                              IARG_CONTEXT,
                                              IARG_ORIG_FUNCPTR,
                                              IARG_END);
                } else if (a1 == -1) {
                    RTN_ReplaceSignatureProbed(rtn, repl,
                                              IARG_PROTOTYPE, proto,
                                              IARG_CONTEXT,
                                              IARG_ORIG_FUNCPTR,
                                              IARG_FUNCARG_ENTRYPOINT_VALUE, (UINT32)a0,
                                              IARG_END);
                } else {
                    RTN_ReplaceSignatureProbed(rtn, repl,
                                              IARG_PROTOTYPE, proto,
                                              IARG_CONTEXT,
                                              IARG_ORIG_FUNCPTR,
                                              IARG_FUNCARG_ENTRYPOINT_VALUE, (UINT32)a0,
                                              IARG_FUNCARG_ENTRYPOINT_VALUE, (UINT32)a1,
                                              IARG_END);
                }
                fprintf(stderr, "[HOOK] hooked %s (%s) in %s\n", rname.c_str(), kind, imgName.c_str());
                fflush(stderr);
            };

            if (lname.find("malloc") != string::npos) {
                PROTO p = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT, rname.c_str(),
                                         PIN_PARG(size_t), PIN_PARG_END());
                try_hook("malloc", p, AFUNPTR(CallMalloc), 0);
            }
            else if (lname.find("calloc") != string::npos) {
                PROTO p = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT, rname.c_str(),
                                         PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());
                try_hook("calloc", p, AFUNPTR(CallCalloc), 0, 1);
            }
            else if (lname.find("realloc") != string::npos) {
                PROTO p = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT, rname.c_str(),
                                         PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG_END());
                try_hook("realloc", p, AFUNPTR(CallRealloc), 0, 1);
            }
            else if (lname.find("free") != string::npos) {
                PROTO p = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT, rname.c_str(),
                                         PIN_PARG(void*), PIN_PARG_END());
                try_hook("free", p, AFUNPTR(CallFree), 0);
            }
        }
    }
}

/* ===== Fini & Usage ===== */
static VOID Fini(INT32 code, VOID*) {
    if (trace) fprintf(trace, "#eof\n");
    if (trace) fclose(trace);
}

static INT32 Usage() {
    PIN_ERROR("This Pintool prints a trace of labeled memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===== Main ===== */
int main(int argc, char* argv[]) {
    PIN_InitSymbols();                // required for probed replacement & symbol names
    if (PIN_Init(argc, argv)) return Usage();

    trace = fopen("pinatrace.out", "w");
    if (!trace) {
        fprintf(stderr, "Cannot open pinatrace.out for writing\n");
        return 2;
    }

    // Instrumentation
    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    INS_AddInstrumentFunction(Instruction, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    // Never returns
    PIN_StartProgram();
    return 0;
}
