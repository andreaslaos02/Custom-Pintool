// ds_demo_reuse_bigger.c
#include <stdio.h>
#include <string.h>
#include "dummy_alloc.h"

// helper: γράφει μέσα στο buffer ώστε να δημιουργηθούν stores/loads
static void touch(char* p, size_t n, char v) {
    for (size_t i = 0; i < n; i += 64) p[i] = v;
    // ένα read για να φαίνεται και load
    volatile char x = p[0];
    (void)x;
}

int main() {
    fprintf(stderr, "[TEST] scenario: alloc small -> free -> alloc bigger at SAME ptr\n");

    // 1) alloc μικρό
    char* a = MEMTRACE_ALLOC(NULL, 4096, "A_small_4K");
    if (!a) return 1;
    touch(a, 4096, 0x11);

    // 2) free (εδώ το pintool πρέπει να κάνει erase το region)
    MEMTRACE_FREE(a, "A_small_4K");

    // 3) alloc μεγαλύτερο (ο dummy allocator θα δώσει το ΙΔΙΟ ptr)
    char* b = MEMTRACE_ALLOC(NULL, 8192, "B_bigger_8K_same_ptr");
    if (!b) return 1;

    // Αν το pintool δεν χειριστεί σωστά, εδώ θα φανεί στη χαρτογράφηση/trace
    touch(b, 8192, 0x22);

    MEMTRACE_FREE(b, "B_bigger_8K_same_ptr");

    fprintf(stderr, "[TEST] done.\n");
    return 0;
}