#include "randstate.h"

gmp_randstate_t state;

//
// randstate_init aims to initialize a random state and set the seed for future random calls.
//
// This function only takes the seed as an argument.
//
// This function returns nothing/void.
//
// This function was basically given to us by Professor Long in the assignment documentation.
//
void randstate_init(uint64_t seed) {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
    return;
}

//
// randstate_clear aims to free any memory used to create the random state.
//
// This function takes no arguments and returns nothing/void.
//
// This function was basically given to us by Professor Long in the assignment documentation.
//
void randstate_clear(void) {
    gmp_randclear(state);
    return;
}
