#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "dummy_alloc.h"        //orizonte ta macros MEMTRACE_ALLOC, MEMTRACE_FREE

#define THREADS 4
#define N       10      // size of array    

typedef struct Node {       //node tis listas
    int value;
    struct Node* next;
} Node;

void* worker(void* arg)         //work tou kathe thread
{
    int tid = (int)(size_t)arg;
    fprintf(stderr, "[Thread %d] started\n", tid);

    Node* head = MEMTRACE_ALLOC(NULL, sizeof(Node), "Node");        //kalei macro gia allocation
    head->value = tid * 100;                                    //tixea timi to tid * 100
    head->next = NULL;                  //lista me ena komvo

    // allocate array
    int* arr = MEMTRACE_ALLOC(NULL, N * sizeof(int), "int[]");      //kalei macro gia allocation gia ton pinaka
    for (int i = 0; i < N; i++) arr[i] = tid * 10 + i;          //arxikopoisi tou pinaka 10 thesewn me tixeies times

    // simulate reads/writes
    for (int i = 0; i < N; i++) {                     //prosthetei 1 se kathe thesi tou pinaka kai prosthetei tin timi tou ston komvo tis listas
        arr[i] += 1;                                //apla gia na iparxei workload gia to pintool mas 
        head->value += arr[i];
    }

    // allocate dynamic array
    double* dyn = MEMTRACE_ALLOC(NULL, 6 * sizeof(double), "DynArr");           //allo allocation gia dynamic array
    for (int i = 0; i < 6; i++) dyn[i] = tid + 0.1 * i;                         //gemizei ton pinaka me tixeies times (doubles)

    // simulate computation
    double sum = 0; 
    for (int i = 0; i < 6; i++) sum += dyn[i];          //prokalw reads ston pinaka gia na ipologisw to sum oste na iparxei workload

    fprintf(stderr, "[Thread %d] sum=%.2f head->value=%d\n", tid, sum, head->value);

    // free allocations
    MEMTRACE_FREE(arr, "int[]");                     //kalei macro gia free
    MEMTRACE_FREE(dyn, "DynArr");                     //kalei macro gia free
    MEMTRACE_FREE(head, "Node");                 //kalei macro gia free
    // to pintool edw kanei lookup kai kanei mark tis perioxes tou region os freed
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