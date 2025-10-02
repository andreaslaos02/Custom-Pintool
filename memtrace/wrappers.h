#pragma once
#include <stddef.h>

void *my_malloc(size_t s);
void *my_calloc(size_t n, size_t sz);
void *my_realloc(void *p, size_t s);
void  my_free(void *p);