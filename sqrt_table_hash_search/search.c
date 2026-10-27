/* Deterministic search for the square-root hash multiplier of bls12_381's Scalar.
 *
 * `SqrtHasher::hash` hashes a key k as (k * hash_mul mod 2^32) >> (32 - SQRT_HASH_BITS). This
 * tries every odd multiplier in ascending order and prints the first ones that are injective on
 * the 256 keys from keys.py.
 *
 *     python3 keys.py > keys.h && cc -O2 -o search search.c && ./search 10 1
 *
 * prints `bits 10 hash_mul 0x60ff5f7b` after ~1.6e9 candidates (about a minute).
 */
#include <stdio.h>
#include <stdlib.h>
#include "keys.h"

int main(int argc, char **argv) {
    int bits = argc > 1 ? atoi(argv[1]) : 10, want = argc > 2 ? atoi(argv[2]) : 1, found = 0;
    unsigned shift = 32 - bits, gen = 0;
    static unsigned stamp[1 << 16];
    for (unsigned long long m = 1; m < (1ULL << 32); m += 2) {
        int ok = 1;
        gen++;
        for (int j = 0; j < 256; j++) {
            unsigned h = ((unsigned)K[j] * (unsigned)m) >> shift;
            if (stamp[h] == gen) { ok = 0; break; }
            stamp[h] = gen;
        }
        if (ok) {
            printf("bits %d hash_mul 0x%08llx\n", bits, m);
            if (++found >= want) return 0;
        }
    }
    printf("bits %d none\n", bits);
    return 1;
}
