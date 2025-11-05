// test_findregion.cpp
//g++ -O2 -std=c++17 test_findregion.cpp -o test_findregion
//./test_findregion
#include <map>
#include <string>
#include <cstdio>
#include <cstdint>
#include <cassert>

using ADDRINT = unsigned long long;

struct Region {
    ADDRINT start;
    size_t  size;
    std::string tag;
};

static std::map<ADDRINT, Region> g_regions;

static const Region* FindRegion(ADDRINT a)
{
    auto it = g_regions.upper_bound(a);   // first region with start > a
    if (it == g_regions.begin()) return nullptr;
    --it;                                 // candidate: start <= a
    const Region& r = it->second;
    if (a >= r.start && a < (r.start + r.size)) return &r;
    return nullptr;
}

static void add_region(ADDRINT start, size_t size, const char* tag)
{
    Region r{start, size, tag ? tag : "?"};
    g_regions[start] = r;
}

// Helper: pretty print hex
static const char* yesno(bool b) { return b ? "YES" : "NO"; }

static void test_addr(ADDRINT a, const char* expectTag) {
    const Region* r = FindRegion(a);
    const char* actual = r ? r->tag.c_str() : "-";
    bool pass = (std::string(actual) == std::string(expectTag));
    std::printf("Lookup a=%#llx  -> tag=%-6s  (expected=%-6s)  [%s]\n",
                (unsigned long long)a, actual, expectTag, pass ? "PASS" : "FAIL");
    if (r) {
        /*std::printf("   candidate: start=%#llx size=%zu  contains? %s (a in [start,%#llx))\n",
                    (unsigned long long)r->start, r->size,
                    yesno(a >= r->start && a < r->start + r->size),
                    (unsigned long long)(r->start + r->size));*/
        std::printf("   candidate: start=%#llx  size=%zu  "
            "end=%#llx  last_byte=%#llx  contains? %s (a in [start,%#llx))\n",
            (unsigned long long)r->start,
            r->size,
            (unsigned long long)(r->start + r->size),
            (unsigned long long)(r->start + r->size - 1),
            yesno(a >= r->start && a < r->start + r->size),
            (unsigned long long)(r->start + r->size));
    }
}

int main() {
    // Στήσε 3 allocations όπως στα παραδείγματα:
    // Node:   [0x1000, 0x1010)
    // int[]:  [0x2000, 0x2040)
    // DynArr: [0x2080, 0x2098)
    add_region(0x1000, 0x10,  "Node");
    add_region(0x2000, 0x40,  "int[]");
    add_region(0x2080, 0x18,  "DynArr");

    std::puts("=== Deterministic tests ===");
    // Πριν από το πρώτο region
    test_addr(0x0fff, "-");          // πριν το 0x1000 → καμία αντιστοίχιση

    // Όρια & μέσα στο 1ο region
    test_addr(0x1000, "Node");       // αρχή Node
    test_addr(0x100f, "Node");       // τελευταίο byte μέσα
    test_addr(0x1010, "-");          // ακριβώς στο τέλος → εκτός (half-open [start,end))

    // Κενό μεταξύ Node και int[]
    test_addr(0x1500, "-");          // κενό → καμία αντιστοίχιση

    // 2ο region (int[])
    test_addr(0x2000, "int[]");      // αρχή int[]
    test_addr(0x203f, "int[]");      // τελευταίο byte μέσα
    test_addr(0x2040, "-");          // τέλος → εκτός

    // 3ο region (DynArr)
    test_addr(0x2080, "DynArr");     // αρχή DynArr
    test_addr(0x2097, "DynArr");     // τελευταίο byte μέσα
    test_addr(0x2098, "-");          // τέλος → εκτός

    // Μετά από όλα
    test_addr(0x3000, "-");          // καμία αντιστοίχιση

    // Mini stress: 2–3 τυχαίες τιμές γύρω από τα όρια
    std::puts("\n=== Boundary fuzz ===");
    ADDRINT probes[] = {
        0x0fff, 0x1000, 0x1001, 0x100f, 0x1010,
        0x1fff, 0x2000, 0x2010, 0x203f, 0x2040,
        0x207f, 0x2080, 0x2090, 0x2097, 0x2098
    };
    for (ADDRINT a : probes) test_addr(a, FindRegion(a) ? FindRegion(a)->tag.c_str() : "-");

    std::puts("\nDone.");
    return 0;
}
