#include <stdio.h>
#include "dummy_alloc.h"

/* Empty implementations — exist only to create stable symbols in the binary.
   They do nothing at runtime (the Pin tool will interpose on them). */

void __memtrace_alloc_site(void* ptr, size_t size, const char* type_tag, const char* func, const char* file, int line) {       // dummy-site allocator
    //fprintf(stderr, "[SITE ALLOC] p=%p size=%zu tag=%s @%s:%d (%s)\n",ptr, size, (type_tag ? type_tag : "?"),(file ? file : "?"), line, (func ? func : "?"));    
    (void)ptr; (void)size; (void)type_tag; (void)func; (void)file; (void)line;
}

void __memtrace_free_site(void* ptr, const char* type_tag, const char* func, const char* file, int line) {  // dummy-site deallocator
    //fprintf(stderr, "[SITE FREE ] p=%p tag=%s @%s:%d (%s)\n",ptr, (type_tag ? type_tag : "?"),(file ? file : "?"), line, (func ? func : "?"));
    (void)ptr; (void)type_tag; (void)func; (void)file; (void)line;
}

/* Anchor to prevent DCE 
__attribute__((used))
static void* __mt_keep[] = { (void*)&__memtrace_alloc_site, (void*)&__memtrace_free_site };*/