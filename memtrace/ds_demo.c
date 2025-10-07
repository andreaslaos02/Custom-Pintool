#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dummy_alloc.h"

/* Macros — caller passes a type tag string literal.
   MT_MALLOC_T("Node", sizeof(Node))
   MT_FREE_T("Node", p) */
#define MT_MALLOC_T(type_str, sz) \
({ void* __p = malloc(sz); __memtrace_alloc_site(__p, (sz), (type_str), __FUNCTION__, __FILE__, __LINE__); __p; })

#define MT_FREE_T(type_str, p) \
do { __memtrace_free_site((p), (type_str), __FUNCTION__, __FILE__, __LINE__); free(p); } while(0)

/* ---------- linked list ---------- */
typedef struct Node {
    int value;
    struct Node* next;
} Node;

Node* make_node(int v) {
    Node* n = (Node*)MT_MALLOC_T("Node", sizeof(Node));
    n->value = v;
    n->next = NULL;
    return n;
}

void free_list(Node* head) {
    Node* cur = head;
    while (cur) {
        Node* nxt = cur->next;
        MT_FREE_T("Node", cur);
        cur = nxt;
    }
}

Node* build_list(int n) {
    Node* head = NULL;
    for (int i = 0; i < n; ++i) {
        Node* x = make_node(i);
        x->next = head;
        head = x;
    }
    return head;
}

/* ---------- dynamic array ---------- */
typedef struct DynArr {
    int *data;
    size_t len;
    size_t cap;
} DynArr;

DynArr* dynarr_create(size_t initial) {
    DynArr* a = (DynArr*)MT_MALLOC_T("DynArr", sizeof(DynArr));
    a->cap = initial ? initial : 4;
    a->len = 0;
    a->data = (int*)MT_MALLOC_T("int[]", a->cap * sizeof(int));
    return a;
}

void dynarr_push(DynArr* a, int v) {
    if (a->len == a->cap) {
        size_t newcap = a->cap * 2;
        int* newdata = (int*)MT_MALLOC_T("int[]", newcap * sizeof(int));
        memcpy(newdata, a->data, a->len * sizeof(int));
        MT_FREE_T("int[]", a->data);
        a->data = newdata;
        a->cap = newcap;
    }
    a->data[a->len++] = v;
}

void dynarr_free(DynArr* a) {
    MT_FREE_T("int[]", a->data);
    MT_FREE_T("DynArr", a);
}

/* ---------- main (small test) ---------- */
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Building list and dynamic array test...\n");

    Node* list = build_list(10);
    DynArr* arr = dynarr_create(4);
    for (int i = 0; i < 20; ++i) dynarr_push(arr, i);

    /* do some reads/writes to create memory accesses */
    for (int i = 0; i < 10; ++i) {
        Node* cur = list;
        int sum = 0;
        while (cur) { sum += cur->value; cur = cur->next; }
        (void)sum;
    }

    for (size_t i = 0; i < arr->len; ++i) {
        arr->data[i] = arr->data[i] * 2;
    }

    /* free structures */
    free_list(list);
    dynarr_free(arr);

    printf("Done.\n");
    return 0;
}