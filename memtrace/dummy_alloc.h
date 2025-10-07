#ifndef DUMMY_ALLOC_H
#define DUMMY_ALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Dummy hooks: non-inline, kept, visible so compiler/linker won't optimize them away.
 * __memtrace_alloc_site: ptr, size, type_tag, func, file, line
 * __memtrace_free_site: ptr, type_tag, func, file, line
 */
__attribute__((noinline, used, visibility("default")))
void __memtrace_alloc_site(void* ptr, size_t size, const char* type_tag, const char* func, const char* file, int line);

__attribute__((noinline, used, visibility("default")))
void __memtrace_free_site(void* ptr, const char* type_tag, const char* func, const char* file, int line);

#ifdef __cplusplus
}
#endif

#endif /* DUMMY_ALLOC_H */