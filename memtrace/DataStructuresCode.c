// ds_demo.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct Node {
    int value;
    struct Node* next;
} Node;

static volatile long sink = 0; // για να μην εξαφανίσει ο compiler τις προσπελάσεις

// Δημιουργία συνδεδεμένης λίστας με n κόμβους και αρχικοποίηση
Node* make_list(size_t n) {
    Node* head = NULL;
    for (size_t i = 0; i < n; ++i) {
        Node* node = (Node*)malloc(sizeof(Node));
        node->value = (int)i;
        node->next = head;
        head = node;
    }
    return head;
}

// Διάσχιση λίστας και άθροιση (read-intensive)
long traverse_list(Node* head) {
    long s = 0;
    for (Node* p = head; p != NULL; p = p->next) {
        s += p->value;     // READ από heap
    }
    return s;
}

// Απελευθέρωση μνήμης λίστας (writes στο allocator metadata)
void free_list(Node* head) {
    while (head) {
        Node* nxt = head->next;
        free(head);        // WRITE/READ σε heap structures
        head = nxt;
    }
}

int main(void) {
    // --- ΔΟΜΗ 1: Δυναμικός πίνακας ---
    const size_t N = 100000;
    int* arr = (int*)malloc(N * sizeof(int));

    // Γεμίζουμε (WRITE) και κάνουμε μερικές αναγνώσεις (READ)
    for (size_t i = 0; i < N; ++i) {
        arr[i] = (int)(i * 3);   // WRITE σε συνεχόμενη μνήμη (array)
    }
    for (size_t i = 0; i < N; i += 64) {
        sink += arr[i];          // READ κάθε 64 στοιχεία για να φανεί pattern
    }

    // --- ΔΟΜΗ 2: Απλά συνδεδεμένη λίστα ---
    const size_t M = 20000;
    Node* head = make_list(M);   // malloc ανά κόμβο (heap pointers διάσπαρτοι)

    // Διάσχιση λίστας (READ) και λίγο WRITE
    long s = traverse_list(head);
    sink += s;

    // Ελαφριά τροποποίηση τιμών (WRITE σε μη συνεχόμενες διευθύνσεις)
    size_t k = 0;
    for (Node* p = head; p != NULL; p = p->next) {
        if ((k++ & 1023) == 0) { // κάθε ~1024 κόμβους
            p->value += 1;       // WRITE σε κόμβους της λίστας
        }
    }

    // Μερικές τυχαίες προσπελάσεις στον πίνακα για να σπάσει η γραμμικότητα
    // (πολύ απλό "pseudo-random" με mod)
    for (size_t t = 1; t < 50000; t *= 2) {
        size_t idx = (t * 2654435761u) % N;
        sink += arr[idx];        // READ "τυχαία" στο array
        arr[idx] ^= (int)t;      // WRITE "τυχαία" στο array
    }

    // Καθαρισμός
    free_list(head);
    free(arr);

    // Εκτύπωση κάτι για να μην αφαιρεθούν τα side-effects
    printf("Done. Sink=%ld\n", sink);
    return 0;
}