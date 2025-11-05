// extra_findregion_fuzz.cpp
// Build: g++ -O2 -std=c++17 extra_findregion_fuzz.cpp -o extra_findregion_fuzz
// Run:   ./extra_findregion_fuzz

#include <map>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cassert>

using ADDRINT = unsigned long long;

struct Region { ADDRINT start; size_t size; std::string tag; };
static std::map<ADDRINT, Region> g_regions;

// === My FindRegion ===
static const Region* FindRegion(ADDRINT a) {
    auto it = g_regions.upper_bound(a);
    if (it == g_regions.begin()) return nullptr;
    --it;
    const Region& r = it->second;
    if (a >= r.start && a < (r.start + r.size)) return &r;
    return nullptr;
}

// Golden (γραμμική) αναζήτηση για σύγκριση
static const Region* GoldenFind(ADDRINT a) {
    const Region* best = nullptr;
    for (auto& kv : g_regions) {
        const Region& r = kv.second;
        if (a >= r.start && a < (r.start + r.size)) {
            if (!best || r.start > best->start) best = &r; // πιο “δεξί” region
        }
    }
    return best;
}

// Φτιάξε N μη επικαλυπτόμενα regions με τυχαίες αποστάσεις
static void make_random_regions(size_t N, uint64_t base, uint64_t gapMin, uint64_t gapMax,
                                uint64_t sizeMin, uint64_t sizeMax, std::mt19937_64& rng) {
    g_regions.clear();
    std::uniform_int_distribution<uint64_t> gapD(gapMin, gapMax);
    std::uniform_int_distribution<uint64_t> sizeD(sizeMin, sizeMax);

    std::vector<Region> tmp;
    uint64_t cursor = base;
    for (size_t i = 0; i < N; ++i) {
        cursor += gapD(rng); // τυχαίο κενό πριν από το region
        uint64_t sz = sizeD(rng);
        tmp.push_back(Region{(ADDRINT)cursor, (size_t)sz, "R"+std::to_string(i)});
        cursor += sz;        // προχώρα μέχρι το τέλος
    }

    // Ανακάτεψε σειρά εισαγωγής
    std::shuffle(tmp.begin(), tmp.end(), rng);
    for (auto& r : tmp) g_regions[r.start] = r;
}

int main() {
    std::mt19937_64 rng(12345);

    // 1) Βασικά στατικά tests με shuffled insertion
    {
        std::vector<Region> rs = {
            {0x1000, 0x10, "Node"},
            {0x2000, 0x40, "int[]"},
            {0x2080, 0x18, "DynArr"},
        };
        std::shuffle(rs.begin(), rs.end(), rng);
        g_regions.clear();
        for (auto& r : rs) g_regions[r.start] = r;

        struct { ADDRINT a; const char* expect; } tests[] = {
            {0x0fff, "-"},
            {0x1000, "Node"},
            {0x100f, "Node"},
            {0x1010, "-"},
            {0x1500, "-"},
            {0x2000, "int[]"},
            {0x203f, "int[]"},
            {0x2040, "-"},
            {0x2080, "DynArr"},
            {0x2097, "DynArr"},
            {0x2098, "-"},
            {0x3000, "-"},
        };
        for (auto &t : tests) {
            auto r = FindRegion(t.a);
            const char* got = r ? r->tag.c_str() : "-";
            assert(std::string(got) == t.expect);
        }
    }

    // 2) Edge case: size=1 regions
    {
        g_regions.clear();
        g_regions[0x5000] = Region{0x5000, 1, "S1"};
        g_regions[0x6000] = Region{0x6000, 1, "S2"};
        assert(FindRegion(0x4fff) == nullptr);
        assert(FindRegion(0x5000) && FindRegion(0x5000)->tag == "S1");
        assert(FindRegion(0x5001) == nullptr);
        assert(FindRegion(0x6000) && FindRegion(0x6000)->tag == "S2");
        assert(FindRegion(0x6001) == nullptr);
    }

    // 3) Fuzz χωρίς επικαλύψεις + σύγκριση με golden
    for (int round = 0; round < 200; ++round) {
        make_random_regions(/*N*/50, /*base*/0x100000, /*gap*/4, 4000,
                            /*size*/1, 512, rng);

        // 200 τυχαίες διευθύνσεις
        std::uniform_int_distribution<uint64_t> addrD(0x0, 0x200000);
        for (int i = 0; i < 200; ++i) {
            ADDRINT a = (ADDRINT)addrD(rng);
            auto r1 = FindRegion(a);
            auto r2 = GoldenFind(a);
            // Συγκρίνουμε pointers ή tags
            auto tag1 = r1 ? r1->tag : std::string("-");
            auto tag2 = r2 ? r2->tag : std::string("-");
            if (tag1 != tag2) {
                std::printf("Mismatch at addr=%#llx  got=%s  expected=%s\n",
                            (unsigned long long)a, tag1.c_str(), tag2.c_str());
                assert(false);
            }
        }
    }

    std::puts("All FindRegion tests passed (verbose fuzz).");
    return 0;
}