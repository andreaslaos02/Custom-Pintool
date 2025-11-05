#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "dummy_alloc.h"

#define THREADS 4
#define N       10

typedef struct Node {
    int value;
    struct Node* next;
} Node;

void* worker(void* arg)
{
    int tid = (int)(size_t)arg;
    fprintf(stderr, "[Thread %d] started\n", tid);

    Node* head = MEMTRACE_ALLOC(NULL, sizeof(Node), "Node");
    head->value = tid * 100;
    head->next = NULL;

    // allocate array
    int* arr = MEMTRACE_ALLOC(NULL, N * sizeof(int), "int[]");
    for (int i = 0; i < N; i++) arr[i] = tid * 10 + i;

    // simulate reads/writes
    for (int i = 0; i < N; i++) {
        arr[i] += 1;
        head->value += arr[i];
    }

    // allocate dynamic array
    double* dyn = MEMTRACE_ALLOC(NULL, 6 * sizeof(double), "DynArr");
    for (int i = 0; i < 6; i++) dyn[i] = tid + 0.1 * i;

    // simulate computation
    double sum = 0;
    for (int i = 0; i < 6; i++) sum += dyn[i];

    fprintf(stderr, "[Thread %d] sum=%.2f head->value=%d\n", tid, sum, head->value);

    // free allocations
    MEMTRACE_FREE(arr, "int[]");
    MEMTRACE_FREE(dyn, "DynArr");
    MEMTRACE_FREE(head, "Node");

    fprintf(stderr, "[Thread %d] finished\n", tid);
    return NULL;
}

int main(void)
{
    pthread_t threads[THREADS];
    fprintf(stderr, "[Main] starting %d threads...\n", THREADS);

    for (int i = 0; i < THREADS; i++)
        pthread_create(&threads[i], NULL, worker, (void*)(size_t)i);

    for (int i = 0; i < THREADS; i++)
        pthread_join(threads[i], NULL);

    fprintf(stderr, "[Main] all threads finished.\n");
    return 0;
}