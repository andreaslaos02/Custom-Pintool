// dummy_alloc_reuse.c
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "dummy_alloc.h"

// Ένα “slot” που πάντα επιστρέφει το ίδιο ptr
static void*  g_base = NULL;
static size_t g_cap  = 0;
static int    g_inuse = 0;

void* __memtrace_alloc_site(void* /*ptr*/, size_t size,
    const char* tag, const char* func, const char* file, int line)
{
    if (size == 0) return NULL;

    // Δώσε μεγάλο capacity μια φορά, ώστε να αντέξει μελλοντικά μεγαλύτερα sizes.
    // (μπορείς να το κάνεις max(64KB, size rounded-up))
    const size_t MINCAP = 64 * 1024;

    if (!g_base) {
        size_t page = (size_t)sysconf(_SC_PAGESIZE);
        size_t cap = size;
        if (cap < MINCAP) cap = MINCAP;
        cap = (cap + page - 1) / page * page;

        g_base = mmap(NULL, cap, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g_base == MAP_FAILED) {
            g_base = NULL;
            perror("mmap");
            return NULL;
        }
        g_cap = cap;
    }

    if (size > g_cap) {
        fprintf(stderr,
            "[dummy_alloc_reuse] ERROR: requested %zu > cap %zu (increase MINCAP)\n",
            size, g_cap);
        return NULL;
    }

    g_inuse = 1;

    fprintf(stderr,
        "[dummy_alloc_reuse] ALLOC %p req=%zu cap=%zu tag=%s @%s:%d (%s)\n",
        g_base, size, g_cap, tag ? tag : "?", file ? file : "?", line, func ? func : "?");

    // IMPORTANT: επιστρέφουμε ΠΑΝΤΑ το ίδιο pointer
    return g_base;
}

void __memtrace_free_site(void* ptr,
  const char* tag, const char* func, const char* file, int line)
{
    fprintf(stderr,
        "[dummy_alloc_reuse] FREE  %p tag=%s @%s:%d (%s)\n",
        ptr, tag ? tag : "?", file ? file : "?", line, func ? func : "?");

    // Δεν κάνουμε munmap/free -> θέλουμε να ξαναχρησιμοποιηθεί το ίδιο ptr
    if (ptr == g_base) g_inuse = 0;
}