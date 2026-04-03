// array_cache_unittest.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

// Orizo tipo dedomenon gia ta modes prosvasis
typedef enum {
    MODE_SEQ = 0,
    MODE_REV,
    MODE_STRIDE,
    MODE_RAND
} access_mode_t;

// Synartisi gia emfanisi odigion xrisis
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <num_elements> <passes> <mode> [stride_or_seed]\n"
        "  mode: seq | rev | stride | rand\n"
        "  stride_or_seed:\n"
        "    stride mode -> stride value\n"
        "    rand mode   -> seed value\n",
        prog);
}

// Gia metatropi tou string pou tha dwsei o user gia to access mode se enum timi.
static access_mode_t parse_mode(const char *s) {
    if (strcmp(s, "seq") == 0)    return MODE_SEQ;
    if (strcmp(s, "rev") == 0)    return MODE_REV;
    if (strcmp(s, "stride") == 0) return MODE_STRIDE;
    if (strcmp(s, "rand") == 0)   return MODE_RAND;

    fprintf(stderr, "Unknown mode: %s\n", s);
    exit(1);
}

// Dimiourgei mia tixeia metathesi ton apo indices me vasi to seed pou tha dwsei o user.
// Xrisimo gia na dimiourgei tixea prosbasi se stoixeia tou pinaka.
static void build_random_permutation(size_t *idx, size_t n, unsigned int seed) {
    for (size_t i = 0; i < n; i++) {
        idx[i] = i;
    }

    srand(seed);
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)(rand() % (int)(i + 1));
        size_t tmp = idx[i];
        idx[i] = idx[j];
        idx[j] = tmp;
    }
}


int main(int argc, char **argv) {
    // elegxos gia ton arithmo ton arguments pou dinei o user
    // To programma apaitei toulaxiston 4 argumens, an einai ligotera termatizei (name,arithmos elemtns,passes,mode)
    if (argc < 4) {
        usage(argv[0]);
        return 1;
    }

    // Diavazei ta arguments pou dinei o user kai ta apothikevei se metavlites.
    size_t n = strtoull(argv[1], NULL, 10);
    size_t passes = strtoull(argv[2], NULL, 10);
    access_mode_t mode = parse_mode(argv[3]);

    // Default values gia stride kai seed an den dwsei o user.
    size_t stride = 1;
    unsigned int seed = 12345;

    // Elegxos gia to num_elements na einai > 0, alliws termatizei me minima lathous.
    if (n == 0) {
        fprintf(stderr, "num_elements must be > 0\n");
        return 1;
    }

    // Control to stride mode. Xriazete akoma mia extra parametros gia to stride. Den epitrepei to 0 giati tha itan idio me seq.
    if (mode == MODE_STRIDE) {
        if (argc < 5) {
            fprintf(stderr, "stride mode requires a stride value\n");
            return 1;
        }
        stride = strtoull(argv[4], NULL, 10);
        if (stride == 0) {
            fprintf(stderr, "stride must be > 0\n");
            return 1;
        }
    }

    // Control tou random mode. Proeretika prepei na dwthei to seed alios perni default timi.
    if (mode == MODE_RAND) {
        if (argc >= 5) {
            seed = (unsigned int)strtoul(argv[4], NULL, 10);
        }
    }

    // Dimiourgia pinaka me desmevsi dinamika tis mnimis gia n = arithmos elements.
    int *arr = (int *)malloc(n * sizeof(int));
    if (!arr) {
        perror("malloc");
        return 1;
    }

    // An to mode einai random, xriazomaste ena pinaka perm pou tha krata tin tixea metathesi ton indices gia accesses.
    size_t *perm = NULL;
    if (mode == MODE_RAND) {
        perm = (size_t *)malloc(n * sizeof(size_t));
        if (!perm) {
            perror("malloc perm");
            free(arr);
            return 1;
        }
        build_random_permutation(perm, n, seed);
    }

    // Gemizoume ton pinaka me times. Mono stores.
    for (size_t i = 0; i < n; i++) {
        arr[i] = (int)i;
    }

    // Kanw print ta stoixeia tis ektelesis.
    printf("PID                : %d\n", getpid());
    printf("Elements           : %zu\n", n);
    printf("Element size       : %zu bytes\n", sizeof(int));
    printf("Dataset size       : %zu bytes\n", n * sizeof(int));
    printf("Passes             : %zu\n", passes);
    printf("Mode               : %s\n", argv[3]);
    if (mode == MODE_STRIDE) {
        printf("Stride             : %zu\n", stride);
    }
    if (mode == MODE_RAND) {
        printf("Seed               : %u\n", seed);
    }
    // perimeni gia na aferesw to signal.
    printf("Sleeping 60 seconds before measured accesses...\n");
    fflush(stdout);

    sleep(60);

    // O arithmos pou tha apothikeutei to apotelesma ton prosvasion gia na min ginei optimize to loop apo ton compiler.
    // Xrisimopoioume to apotelesma pou diavazoume gia na min to afairesi o compiler gia optimise.
    volatile uint64_t sink = 0;

    // main measure loop. Epanalamvanei to access pattern analoga me ton arithmo ton passes pou dinei o user.
    for (size_t p = 0; p < passes; p++) {
        switch (mode) {
            // Sarosi tou pinaka apo tin arxi mexri to telos.
            case MODE_SEQ:
                for (size_t i = 0; i < n; i++) {
                    sink += (uint64_t)arr[i];       // 1 load
                    arr[i] += 1;              // 1 store + 1 load
                }
                break;
            // Sarosi tou pinaka apo to telos mexri tin arxi.
            case MODE_REV:
                for (size_t i = n; i > 0; i--) {
                    size_t k = i - 1;
                    sink += (uint64_t)arr[k];
                    arr[k] += 1;
                }
                break;
            // Sarosi tou pinaka me vasi to stride. Prokeitai na sarwsei ta stoixeia pou briskontai se diafora steps me vasi to stride.
            // Perna apo ola ta stoixeia oxi mono apo ena iposinolo.
            case MODE_STRIDE:
                for (size_t base = 0; base < stride; base++) {
                    for (size_t i = base; i < n; i += stride) {
                        sink += (uint64_t)arr[i];
                        arr[i] += 1;
                    }
                }
                break;
            // Kanei access endelos tixea.
            case MODE_RAND:
                for (size_t i = 0; i < n; i++) {
                    size_t k = perm[i];
                    sink += (uint64_t)arr[k];
                    arr[k] += 1;
                }
                break;
        }
    }

    printf("Final sink         : %llu\n", (unsigned long long)sink);

    free(perm);
    free(arr);
    return 0;
}