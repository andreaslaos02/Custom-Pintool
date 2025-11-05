#ifndef DUMMY_ALLOC_H
#define DUMMY_ALLOC_H

#include <stddef.h>

// Wrappers που καλούνται από το instrumented πρόγραμμα.
// Το pintool κάνει hook σε αυτές.
void* __memtrace_alloc_site(void* ptr, size_t size,
                            const char* type_tag,
                            const char* func, const char* file, int line);

void  __memtrace_free_site(void* ptr, const char* type_tag,
                           const char* func, const char* file, int line);

// Macros για πιο καθαρή χρήση μέσα στο code.
#define MEMTRACE_ALLOC(ptr, size, tag) \
    __memtrace_alloc_site(ptr, size, tag, __func__, __FILE__, __LINE__)

#define MEMTRACE_FREE(ptr, tag) \
    __memtrace_free_site(ptr, tag, __func__, __FILE__, __LINE__)

#endif