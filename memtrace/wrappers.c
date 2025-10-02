// wrappers.c
#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

NOINLINE void *my_malloc(size_t s)  { return malloc(s); }
NOINLINE void *my_calloc(size_t n, size_t sz) { return calloc(n, sz); }
NOINLINE void *my_realloc(void *p, size_t s)  { return realloc(p, s); }
NOINLINE void my_free(void *p) { free(p); }