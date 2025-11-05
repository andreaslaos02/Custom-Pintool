// test_findregion_cases.cpp
// Build: g++ -O2 -std=c++17 test_findregion_cases.cpp -o test_findregion_cases
// Run (summary):      ./test_findregion_cases
// Run (verbose):      ./test_findregion_cases -v
// Run (very-verbose): ./test_findregion_cases -vv   (δείχνει και candidate γραμμές)

#include <map>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>
#include <cassert>
#include <cstring>

using ADDRINT = unsigned long long;

struct Region {
    ADDRINT start;
    size_t  size;
    std::string tag;
};

static std::map<ADDRINT, Region> g_regions;

// === Η δική σου FindRegion (απαράλλαχτη) ===
/*static const Region* FindRegion(ADDRINT a)
{
    auto it = g_regions.upper_bound(a);   // first region with start > a
    if (it == g_regions.begin()) return nullptr;
    --it;                                 // candidate: start <= a
    const Region& r = it->second;
    if (a >= r.start && a < (r.start + r.size)) return &r;  // half-open [start, end)
    return nullptr;
}*/

// === Code Under Test ===
static const Region* FindRegion(ADDRINT a) {
    auto it = g_regions.upper_bound(a);    // first start > a
    if (it == g_regions.begin()) return nullptr;
    --it;                                  // candidate: start <= a
    const Region& r = it->second;
    // Προσοχή σε overflow: (r.start + r.size)
    if (r.size != 0 && a >= r.start && a < (r.start + r.size)) return &r;
    return nullptr;
}

static void add_region(ADDRINT start, size_t size, const char* tag)
{
    g_regions[start] = Region{start, size, tag ? tag : "?"};
}

struct Case {
    const char* name;
    ADDRINT addr;
    const char* expectTag;  // "-" για no-match
};

static const char* yesno(bool b) { return b ? "YES" : "NO"; }

int main(int argc, char** argv)
{
    bool verbose = false;      // -v
    bool veryVerbose = false;  // -vv (επιπλέον candidate lines)

    if (argc >= 2) {
        if (std::strcmp(argv[1], "-v") == 0) verbose = true;
        else if (std::strcmp(argv[1], "-vv") == 0) { verbose = true; veryVerbose = true; }
    }

    // Περίπτωση σαν το πρόγραμμα σου
    add_region(0x1000, 0x10,  "Node");   // [0x1000,0x1010)
    add_region(0x2000, 0x40,  "int[]");  // [0x2000,0x2040)
    add_region(0x2080, 0x18,  "DynArr"); // [0x2080,0x2098)

    // Test cases (ομαδοποιημένα: όρια, κενά, μέσα στα regions, πέρα από όλα)
    std::vector<Case> cases = {
        {"before first",        0x0fff, "-"},
        {"Node start",          0x1000, "Node"},
        {"Node last byte",      0x100f, "Node"},
        {"Node end (outside)",  0x1010, "-"},
        {"gap Node-int[]",      0x1500, "-"},
        {"int[] start",         0x2000, "int[]"},
        {"int[] last byte",     0x203f, "int[]"},
        {"int[] end (outside)", 0x2040, "-"},
        {"DynArr start",        0x2080, "DynArr"},
        {"DynArr last byte",    0x2097, "DynArr"},
        {"DynArr end (outside)",0x2098, "-"},
        {"after all",           0x3000, "-"},
        // Μερικά “σύνορα” επιπλέον
        {"border 0x1001",       0x1001, "Node"},
        {"border 0x2010",       0x2010, "int[]"},
        {"border 0x2090",       0x2090, "DynArr"},
    };

    unsigned fails = 0;
    if (verbose) std::puts("=== FindRegion detailed results ===");

    for (size_t i = 0; i < cases.size(); ++i) {
        const auto& c = cases[i];
        const Region* r = FindRegion(c.addr);
        const char* got = r ? r->tag.c_str() : "-";
        bool pass = (std::string(got) == std::string(c.expectTag));
        fails += pass ? 0u : 1u;

        if (verbose) {
            std::printf("[%02zu] %-22s  addr=%#llx  expect=%-6s  got=%-6s  => %s\n",
                        i, c.name, (unsigned long long)c.addr, c.expectTag, got,
                        pass ? "PASS" : "FAIL");
            if (veryVerbose) {
                if (r) {
                    auto end = r->start + r->size;
                    std::printf("     candidate: start=%#llx  size=%zu  end=%#llx  last_byte=%#llx  contains? %s\n",
                                (unsigned long long)r->start, r->size,
                                (unsigned long long)end,
                                (unsigned long long)(end - 1),
                                yesno(c.addr >= r->start && c.addr < end));
                } else {
                    std::puts("     candidate: (none)");
                }
            }
        }
    }

    if (fails == 0) {
        std::puts("All FindRegion tests passed.");
        return 0;
    } else {
        std::printf("%u tests FAILED.\n", fails);
        return 1;
    }
}