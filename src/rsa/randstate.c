#include "randstate.h"

gmp_randstate_t state;

//
// Initializes a random state and set the seed for future random calls.
//
// seed: the seed for the random state
//
void randstate_init(uint64_t seed) {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
    return;
}

//
// Frees any memory used to create the random state.
//
void randstate_clear(void) {
    gmp_randclear(state);
    return;
}
