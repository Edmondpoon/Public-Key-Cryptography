#include "numtheory.h"
#include "randstate.h"

// Calculates the greatest common divisor between two numbers.
//
// d: the greatest common divisor
// a: the first input value
// b: the second input value
void gcd(mpz_t d, mpz_t a, mpz_t b) {
    mpz_t op1, op2, temp;
    mpz_inits(op1, op2, temp, NULL);
    mpz_set(op1, a), mpz_set(op2, b);
    // Calculates the gcd
    while (mpz_cmp_si(op2, 0) != 0) {
        mpz_set(temp, op2);
        mpz_mod(op2, op1, op2);
        mpz_set(op1, temp);
    }
    mpz_set(d, op1);
    mpz_clears(temp, op1, op2, NULL);
}

// Finds the modular multiplicative inverse of a number given a modulo n.
//
// i: the modular multiplicative inverse
// a: the number to use
// n: the modulus
void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    mpz_t r, r_prime, t, t_prime, q, temp;
    mpz_inits(r, r_prime, t, t_prime, q, temp, NULL);
    mpz_set(r, n), mpz_set(r_prime, a);
    mpz_set_ui(t, 0), mpz_set_ui(t_prime, 1);
    while (mpz_cmp_ui(r_prime, 0) != 0) {
        mpz_fdiv_q(q, r, r_prime);
        mpz_mul(temp, q, r_prime);
        mpz_sub(temp, r, temp);
        mpz_set(r, r_prime);
        mpz_set(r_prime, temp);
        mpz_mul(temp, q, t_prime);
        mpz_sub(temp, t, temp);
        mpz_set(t, t_prime);
        mpz_set(t_prime, temp);
    }
    if (mpz_cmp_ui(r, 1) > 0) {
        mpz_set_ui(i, 0);
        mpz_clears(r, r_prime, t, t_prime, q, temp, NULL);
        return;
    }

    if (mpz_cmp_ui(t, 0) < 0) {
        mpz_add(t, t, n);
    }
    mpz_set(i, t);
    mpz_clears(r, r_prime, t, t_prime, q, temp, NULL);
    return;
}

// Finds the modulus of base to the power of exponent.
//
// expoenent: the exponent power
// modulus  : the modulus to use
// base     : the base of the exponent
// out      : the modulus of the product
void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {
    mpz_t approx, t_base, t_exponent;
    mpz_inits(approx, t_exponent, t_base, NULL);
    mpz_set_ui(approx, 1); // Approximate value
    mpz_set(t_base, base); // Current base
    mpz_set(t_exponent, exponent); // Current exponent
    while (mpz_cmp_ui(t_exponent, 0) > 0) { // While we have more exponents to calculate
        if (mpz_odd_p(t_exponent)) {
            mpz_mul(approx, approx, t_base);
            mpz_mod(approx, approx, modulus);
        }
        mpz_mul(t_base, t_base, t_base);
        mpz_mod(t_base, t_base, modulus); // Next power of two
        mpz_fdiv_q_ui(t_exponent, t_exponent, 2);
    }
    mpz_set(out, approx);
    mpz_clears(approx, t_base, t_exponent, NULL);
}

// Determines whether a number has a high chance of being a prime number.
//
// iters: the number of iterations to use for the Miller-Rabin primality testing
// n    : the number to check
bool is_prime(mpz_t n, uint64_t iters) {
    // Base case of 1, 2 and 3 since those break the Miller-Rabin primality theorem
    // Mainly, we cant pick an a within the range [n, n - 2]
    if (!mpz_cmp_ui(n, 2) || !mpz_cmp_ui(n, 3)) {
        return true;
    } else if (!mpz_cmp_ui(n, 1) || !mpz_cmp_ui(n, 0)) {
        return false;
    } else if (mpz_even_p(n)) { // Even numbers other than 2 can't be prime
        return false;
    }
    // Find a s and r such that r is odd and n - 1 = (2^s) * r
    int64_t exponent = 0;
    mpz_t temp, r, n_sub1, two;
    mpz_inits(two, r, n_sub1, temp, NULL);
    mpz_set_ui(two, 2);
    mpz_sub_ui(n_sub1, n, 1);
    mpz_set(r, n_sub1);
    // The idea below is from Professor Long
    while (mpz_even_p(r)) {
        mpz_fdiv_q(r, r, two);
        exponent += 1;
    }
    mpz_t iter, random, n_sub2, y, j, s_sub1;
    mpz_inits(iter, y, j, s_sub1, n_sub2, random, NULL);

    // Main portion of the Miller-Rabin primality test
    for (mpz_set_ui(iter, 1); mpz_cmp_ui(iter, iters) < 0; mpz_add_ui(iter, iter, 1)) {
        mpz_sub_ui(n_sub2, n, 3);
        if (mpz_cmp_ui(n_sub2, 3) < 0) {
            mpz_set_ui(random, 2);
        } else {
            mpz_urandomm(random, state, n_sub2);
            mpz_add_ui(random, random, 2);
        }
        pow_mod(y, random, r, n);
        if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, n_sub1) != 0) {
            mpz_set_ui(j, 1);
            mpz_set_ui(s_sub1, exponent - 1);
            while (exponent - 1 >= 0 && mpz_cmp(j, s_sub1) <= 0 && mpz_cmp(y, n_sub1) != 0) {
                pow_mod(y, y, two, n);
                if (mpz_cmp_ui(y, 1) == 0) {
                    mpz_clears(r, two, n_sub1, iter, random, n_sub2, y, j, s_sub1, NULL);
                    return false;
                }
                mpz_add_ui(j, j, 1);
            }
            if (mpz_cmp(y, n_sub1) != 0) {
                mpz_clears(r, two, n_sub1, iter, random, n_sub2, y, j, s_sub1, NULL);
                return false;
            }
        }
    }
    mpz_clears(r, two, n_sub1, iter, random, n_sub2, y, j, s_sub1, NULL);
    return true;
}

// Generates a prime that is at least bits number of bits long.
//
// iters: the number of iterations for the Miller-Rabin primality testing
// bits : the minimum number of bits the prime number must be
// p    : the final prime number
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    mpz_urandomb(p, state, bits + 1);
    // Finds a random prime number that is at least bits long
    while (mpz_sizeinbase(p, 2) < bits || !is_prime(p, iters)) {
        mpz_urandomb(p, state, bits + 1);
    }
    return;
}
