#include "numtheory.h"
#include "randstate.h"
#include <stdlib.h>

//
// rsa_make_pub aims to generate a public RSA key.
//
// This function takes 6 arguments: p, q, n, e, nbits, and iters. Nbits and iters represent the aspects the user wants
// for the prime numbers. p and q represent the variables we store the two prime numbers into. n represents the product
// of the primes and e represents the public exponent.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {
    // Avoid a lower and upper bound of 0
    if (nbits < 4) {
        return;
    }
    bool found = false;
    mpz_t lower, upper, bits1, bits2, temp;
    mpz_inits(lower, upper, bits1, bits2, temp, NULL);

    // Calculates the range of bits to ensure both primes are around the same number of bits
    mpz_set_ui(lower, nbits / 4);
    mpz_mul_ui(upper, lower, 3);
    mpz_sub(temp, upper, lower);
    mpz_urandomm(bits1, state, temp);
    mpz_add(bits1, bits1, lower);
    mpz_set_ui(bits2, nbits - mpz_get_ui(bits1));

    while (!found) { // Until we get good enough primes
        make_prime(p, mpz_get_ui(bits1), iters);
        make_prime(q, mpz_get_ui(bits2), iters);
        mpz_mul(n, p, q);
        // Ensures the product of primes satisfies the equation log2(n) >= nbits
        if (mpz_sizeinbase(n, 2) >= nbits) {
            found = true;
        }
    }

    mpz_t left, right, totient;
    mpz_inits(left, right, totient, NULL);
    mpz_sub_ui(left, p, 1);
    mpz_sub_ui(right, q, 1);
    mpz_mul(totient, left, right); // totient(n) = (p - 1) * (q - 1)

    found = false;
    mpz_t random, divisor;
    mpz_inits(random, divisor, NULL);
    // Finds public exponent
    while (!found) {
        mpz_urandomb(random, state, nbits);
        gcd(divisor, random, totient);
        if (mpz_cmp_ui(divisor, 1) == 0) {
            found = true;
            mpz_set(e, random);
        }
    }
    mpz_clears(lower, upper, bits1, bits2, temp, left, right, totient, random, divisor, NULL);
    return;
}

//
// rsa_write_pub aims to write out the public key and a signature to a file.
//
// This function has 5 arguments: n, e, s, username, and pbfile. Username represents the name of the user while pbfile
// represents the file to write the key to. Lastly, n, e, and s represent the aspects of the public key and the user's
// signature.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile, "%Zx\n", n);
    gmp_fprintf(pbfile, "%Zx\n", e);
    gmp_fprintf(pbfile, "%Zx\n", s);
    gmp_fprintf(pbfile, "%s\n", username);
    return;
}

//
// rsa_read_pub aims to read a public key from a file.
//
// This function has 5 arguments: n, e, s, username, and pbfile. Username represents the name of the user while pbfile
// represents the file to read the key from. Lastly, n, e, and s represent the aspects of the public key and the user's
// signature.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%Zx\n", n);
    gmp_fscanf(pbfile, "%Zx\n", e);
    gmp_fscanf(pbfile, "%Zx\n", s);
    gmp_fscanf(pbfile, "%s\n", username);
    return;
}

//
// rsa_make_priv aims to generate a private RSA key.
//
// This function takes 4 arguments: p, q, e, and d. The arguments p and q are the prime numbers used in the public key.
// The argument e represents the public exponent from the public key too while d represents the variable we store the
// private key to.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t p1, q1, totient;
    mpz_inits(p1, q1, totient, NULL);
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(totient, p1, q1);
    mod_inverse(d, e, totient);
    mpz_clears(p1, q1, totient, NULL);
    return;
}

//
// rsa_write_priv aims to write out the private key to a file.
//
// This function has 3 arguments: n, d, and pvfile. Pvfile represents the file to write the key to. Lastly, n and d
// represent the aspects of the private key.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile, "%Zx\n", n);
    gmp_fprintf(pvfile, "%Zx\n", d);
    return;
}

//
// rsa_read_priv aims to read a private key from a file.
//
// This function has 3 arguments: n, d, and pvfile. Pvfile represents the file to read the key from. Lastly, n and d
// represent the aspects of the private key.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile, "%Zx\n", n);
    gmp_fscanf(pvfile, "%Zx\n", d);
    return;
}

//
// rsa_encrypt aims to encrypt a message using the public key.
//
// This function takes 4 arguments: c, m, e, and n. C and m represent the encrypted message and original message
// repsectively. Lastly, e and n represent the aspects of the public key.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
    return;
}

//
// rsa_encrypt_file aims to fully encrypt a file's content and write it to a file.
//
// This function takes 4 arguments: infile, outfile, n, and e. Infile and outfile represent the file to encrypt and file
// to write to respectively. Lastly, n and e represent the aspects of the public key.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    mpz_t encrypted, size, message;
    mpz_inits(encrypted, size, message, NULL);

    mpz_set_ui(size, mpz_sizeinbase(n, 2) - 1);
    mpz_fdiv_q_ui(size, size, 8); // Size of block
    if (mpz_cmp_ui(size, 1) < 0) {
        mpz_clears(size, message, encrypted, NULL);
        fprintf(stderr, "Invalid size less than 1.\n");
        return;
    }

    uint8_t *block = (uint8_t *) calloc(mpz_get_ui(size) + 1, sizeof(uint8_t));
    if (!block) {
        mpz_clears(size, message, encrypted, NULL);
        free(block);
        fprintf(stderr, "Unable to allocate memory for the block.\n");
        return;
    }

    block[0] = 0xFF;
    int64_t read = 0;
    while ((read = fread(block + 1, sizeof(uint8_t), mpz_get_ui(size) - 1, infile)) > 0) {
        // Convert bytes into mpz hexstrings
        mpz_import(message, read + 1, 1, sizeof(uint8_t), 1, 0, block);
        rsa_encrypt(encrypted, message, e, n);
        gmp_fprintf(outfile, "%Zx\n", encrypted);
    }
    mpz_clears(size, message, encrypted, NULL);
    free(block);
    return;
}

//
// rsa_decrypt aims to decrypt a message using the private key.
//
// This function takes 4 arguments: c, m, d, and n. C and m represent the encrypted message and decrypted message
// repsectively. Lastly, d and n represent the aspects of the private key.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
    return;
}

//
// rsa_decrypt_file aims to fully decrypt a file's content and write it to a file.
//
// This function takes 4 arguments: infile, outfile, n, and d. Infile and outfile represent the file to decrypt and file
// to write to respectively. Lastly, n and d represent the aspects of the private key.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    mpz_t message, decrypted, size;
    mpz_inits(message, decrypted, size, NULL);

    mpz_set_ui(size, mpz_sizeinbase(n, 2) - 1);
    mpz_fdiv_q_ui(size, size, 8); // Size of block
    uint64_t read = 0;
    if (mpz_cmp_ui(size, 1) < 0) {
        mpz_clears(message, decrypted, size, NULL);
        fprintf(stderr, "Invalid size less than 1.\n");
        return;
    }

    uint8_t *block = (uint8_t *) calloc(mpz_get_ui(size), sizeof(uint8_t));
    if (!block) {
        mpz_clears(size, message, decrypted, NULL);
        free(block);
        fprintf(stderr, "Unable to allocate memory for the block.\n");
        return;
    }
    while (gmp_fscanf(infile, "%Zx\n", message) > 0) {
        // Converts an mpz hexstring into an array of bytes
        rsa_decrypt(decrypted, message, d, n);
        mpz_export(block, &read, 1, sizeof(uint8_t), 1, 0, decrypted);
        for (uint64_t i = 1; i < read; i++) {
            gmp_fprintf(outfile, "%c", block[i]);
        }
    }
    free(block);
    mpz_clears(message, decrypted, size, NULL);
    return;
}

//
// rsa_sign aims to sign the user's username to allow the recipient of a message to know the sender of the message.
//
// This function takes 4 arguments: s, m, d, and n. The arguments d and n represent the apsects of the private key while
// s and m represent the signature and the user's name respectively.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
    return;
}

//
// rsa_verify aims to verify the sender of the message.
//
// This function takes 4 arguments: m, s, e, and n. The arguments e and n represent the apsects of the public key while
// s and m represent the signature and the user's name respectively.
//
// This function returns nothing/void.
//
// Note that this function is based on and build off of the given ideas by Professor Long in the assignment documentation.
//
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t t;
    mpz_init(t);
    pow_mod(t, s, e, n);
    bool val = (mpz_cmp(t, m) == 0);
    mpz_clear(t);
    return val;
}
