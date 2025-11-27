#include "dummy_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h> // Keep for compatibility if needed, but the lock is gone

// static pthread_mutex_t alloc_lock = PTHREAD_MUTEX_INITIALIZER; // ΑΦΑΙΡΕΘΗΚΕ

void* __memtrace_alloc_site(void* ptr, size_t size,
                            const char* type_tag,
                            const char* func, const char* file, int line)
{
    // ΑΦΑΙΡΕΘΗΚΕ: pthread_mutex_lock(&alloc_lock);

    void* p = malloc(size);
    if (!p) {
        fprintf(stderr, "[dummy_alloc] malloc failed @%s:%d (%s)\n", file, line, func);
        // ΑΦΑΙΡΕΘΗΚΕ: pthread_mutex_unlock(&alloc_lock);
        return NULL;
    }

    // Optional diagnostic print 
    fprintf(stderr, "[dummy_alloc] ALLOC %p size=%zu tag=%s @%s:%d (%s)\n",
            p, size, type_tag ? type_tag : "-", file, line, func);

    // ΑΦΑΙΡΕΘΗΚΕ: pthread_mutex_unlock(&alloc_lock);

    return p;
}

void __memtrace_free_site(void* ptr, const char* type_tag,
                          const char* func, const char* file, int line)
{
    if (!ptr) return;
    // ΑΦΑΙΡΕΘΗΚΕ: pthread_mutex_lock(&alloc_lock);

    // Optional diagnostic print
    fprintf(stderr, "[dummy_alloc] FREE  %p tag=%s @%s:%d (%s)\n",
            ptr, type_tag ? type_tag : "-", file, line, func);

    free(ptr);
    // ΑΦΑΙΡΕΘΗΚΕ: pthread_mutex_unlock(&alloc_lock);
}