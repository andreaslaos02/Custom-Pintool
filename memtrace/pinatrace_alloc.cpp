// pinatrace_alloc.cpp — trace R/W με labeling από dummy alloc sites
#include "pin.H"
#include <map>
#include <string>
#include <cstdio>
#include <cstdint>

using std::string;

// ---------- Region map: start -> Region ----------
// Κρατάμε metadata για κάθε allocation που γίνεται μέσω των dummy wrappers
// (tag, μέγεθος, αν έχει γίνει free) ώστε να τα τυπώνουμε στα R/W traces.
// Χρησιμοποιούμε map για να μπορούμε να κάνουμε εύκολα lookup με διευθύνσεις
// που δεν είναι απαραίτητα οι αρχικές (π.χ. μέσα σε ένα array).
// Δεν απελευθερώνουμε τα regions στο free, για να μπορούμε να ανιχνεύουμε
// UAF accesses. 
// otan to pintool vlepei ena allocation apo to hook (CallAllocSite) enimerwnei to map me ena entry gia to allocation
struct Region {
    ADDRINT start;      //arxiki diefthinsi tou allocation
    size_t  size;       //megethos allocation se bytes
    string  tag;        //type of data (π.χ. "Node", "int[]", "DynArr" κλπ)
    bool    freed;   // true αν έχει γίνει free (UAF detection)
    Region() : start(0), size(0), tag("-"), freed(false) {}
};

static std::map<ADDRINT, Region> g_regions; // keyed by start

// ---------- outputs ----------
static FILE* tracef = nullptr; // pinatrace.out (R/W + tag + size + state)
static FILE* logf   = nullptr; // pintool.log   (HOOK/ALLOC/FREE)


// ---------- lookup helper ----------
// βρίσκει το region που περιέχει τη διεύθυνση a (ή nullptr αν δεν υπάρχει)
// Αν υπάρχει region στο map που ξεκινά πριν ή στην a και το a μικρότερο από start+size, τότε ανήκει στο region.
// Χρησιμοποιείται για να βρούμε αν μια διεύθυνση που προσπελάστηκε ανήκει σε κάποιο allocation.
// poliplokotita: log(n) me n ta allocations
static const Region* FindRegion(ADDRINT a)
{
    auto it = g_regions.upper_bound(a);   // πρώτο start > a
    if (it == g_regions.begin()) return nullptr;
    --it;                                 // start <= a             //check if a is in the region
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
//  ---------- record memory accesses ----------
// se kathe klisi tou RecordRead elegxei an i dieuthinsi pou proselthike anhkei se kapoio apo ta regions pou exei kataxwrisei sto map kanontas lookup me tin FindRegion.
// An anikei se kapoio region tote grafw sto tracef(pinatrace.out) to ip, tin dieuthinsi pou proselthike, to tag, to megethos kai an exei ginei free
// An den anikei se kanena region (den exei kataxwrithi apo to pintool) tote grafw to ip, tin dieuthinsi pou proselthike kai ena '-' (mono gia to version tis function pou tiponei olo to memtrace)
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
// ---------- record memory accesses ----------
// se kathe klisi tou RecordWrite elegxei an i dieuthinsi pou proselthike anhkei se kapoio apo ta regions pou exei kataxwrisei sto map kanontas lookup me tin FindRegion.
// An anikei se kapoio region tote grafw sto tracef(pinatrace.out) to ip, tin dieuthinsi pou proselthike, to tag, to megethos kai an exei ginei free
// An den anikei se kanena region (den exei kataxwrithi apo to pintool) tote grafw to ip, tin dieuthinsi pou proselthike kai ena '-' (mono gia to version tis function pou tiponei olo to memtrace)
static VOID RecordWrite(VOID* ip, VOID* addr)
{
    const Region* r = FindRegion((ADDRINT)addr);
    if (!r) return; // αγνόησε αν δεν ανήκει σε καταγεγραμμένο region

    fprintf(tracef, "%p: W %p %s size=%zu state=%s\n",
            ip, addr, r->tag.c_str(), r->size, r->freed ? "FREED" : "ALLOC");
}


//kalite apo to INS_AddInstrumentFunction gia kathe instruction kai eisagei predicated calls gia kathe load/store 
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
// pernw apo ta arguments ta dedomena pou xreiazomai gia to trace
// dimiourgw to neo entry sto map/region me ta dedomena apo ta arguments.
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
        if (logf) {     //grafw proeretika sto pinatrace.log ta allocations kai ta stoixeia pou ta exw kataxwrisei sto map
            fprintf(logf, "[ALLOC] p=%p size=%zu tag=%s @%s:%d (%s)\n",
                    ptr, size, r.tag.c_str(),
                    file ? file : "?", line, func ? func : "?");
        }
    }
}

// to free den afairei to region apo to map, alla to markarei san freed
// ara pernw mono to ptr apo ta arguments, vriskei to region sto map kai to markarei san freed
// gia na mporoume na kanoume UAF (use after free )detection
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
        if (logf) {     //grafw proeretika sto pinatrace.log ta allocations kai ta stoixeia pou ta exw kataxwrisei sto map
            fprintf(logf, "[FREE ] p=%p tag=%s @%s:%d (%s)\n",
                    ptr, type_tag ? type_tag : "?",
                    file ? file : "?", line, func ? func : "?");
        }
    }
}

// ---------- hook σε __memtrace_alloc_site / __memtrace_free_site ----------
// to tool kanei loop se oles tis routines twn images kai psaxnei routines me onoma p periexei __memtrace_alloc_site / __memtrace_free_site
//kai trexei tin antistoixi CallAllocSite / CallFreeSite me ta idia arguments anti na treksi i arxiki sinartisi.
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
                    IARG_PROTOTYPE, p, IARG_CONTEXT, IARG_ORIG_FUNCPTR, //i IARG_ORIG_FUNCPTR einai to pointer stin arxiki sinartisi (dinatotita ektelesis arxikis sinartisis mesa apo to pintool)
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
    INS_AddInstrumentFunction(Instruction, 0);  // trace R/W (katagrafei kathe instruction pou exei mnimiaki prosbash)--kaleite i Instruction fuction gia kathe instruction
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram(); // JIT mode — δεν επιστρέφει
    return 0;
}