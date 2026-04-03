// ./linked_list_unittest 10000 10

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* --------------------------------------------------
 * Node της linked list
 * -------------------------------------------------- */
typedef struct Node {
    int value;           // δεδομένο
    struct Node *next;   // pointer στο επόμενο node
} Node;


/* --------------------------------------------------
 * Δημιουργεί linked list με n στοιχεία
 * -------------------------------------------------- */
Node* create_list(int n) {
    Node *head = NULL;

    for (int i = 0; i < n; i++) {
        Node *new_node = (Node*) malloc(sizeof(Node)); // ALLOC
        if (!new_node) {
            perror("malloc failed");
            exit(1);
        }

        new_node->value = i;     // STORE
        new_node->next = head;   // STORE

        head = new_node;         // STORE
    }

    return head;
}


/* --------------------------------------------------
 * Traverse (pointer chasing)
 * -------------------------------------------------- */
long long traverse_list(Node *head) {
    long long sum = 0;

    Node *curr = head;

    while (curr != NULL) {
        sum += curr->value;   // LOAD
        curr = curr->next;    // LOAD (pointer chasing)
    }

    return sum;
}


/* --------------------------------------------------
 * Update values (writes)
 * -------------------------------------------------- */
void update_list(Node *head) {
    Node *curr = head;

    while (curr != NULL) {
        curr->value += 1;   // STORE
        curr = curr->next;  // LOAD
    }
}


/* --------------------------------------------------
 * Free list (free events)
 * -------------------------------------------------- */
void free_list(Node *head) {
    Node *curr = head;

    while (curr != NULL) {
        Node *next = curr->next;  // LOAD
        free(curr);               // FREE
        curr = next;
    }
}


/* --------------------------------------------------
 * Random pointer chasing (πολύ σημαντικό για cache)
 * -------------------------------------------------- */
void random_access(Node **array, int n, int steps) {
    int idx = rand() % n;

    for (int i = 0; i < steps; i++) {
        Node *node = array[idx];   // LOAD
        idx = node->value % n;     // LOAD + compute
    }
}


/* --------------------------------------------------
 * Main workload
 * -------------------------------------------------- */
int main(int argc, char *argv[]) {

    if (argc < 3) {
        printf("Usage: %s <num_nodes> <iterations>\n", argv[0]);
        return 1;
    }

    int n = atoi(argv[1]);
    int iters = atoi(argv[2]);

    srand(time(NULL));

    printf("Creating list with %d nodes...\n", n);

    Node *head = create_list(n);

    /* --------------------------------------------------
     * Δημιουργούμε array από pointers για random access
     * -------------------------------------------------- */
    Node **array = malloc(n * sizeof(Node*));  // ALLOC

    Node *curr = head;
    for (int i = 0; i < n; i++) {
        array[i] = curr;   // STORE
        curr = curr->next; // LOAD
    }

    /* --------------------------------------------------
     * Workload loop
     * -------------------------------------------------- */
    long long total = 0;

    for (int i = 0; i < iters; i++) {
        total += traverse_list(head);  // sequential access
        update_list(head);             // writes
        random_access(array, n, n);    // random pointer chasing
    }

    printf("Done. Total = %lld\n", total);

    /* --------------------------------------------------
     * Cleanup
     * -------------------------------------------------- */
    free(array);
    free_list(head);

    return 0;
}