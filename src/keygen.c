#include "numtheory.h"
#include "rsa.h"
#include "randstate.h"
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <sys/stat.h>

#define OPTIONS "b:i:n:d:s:vh"
#define VERBOSE true
#define BASE10  10
#define BITS    256
#define ITERS   50

enum Files { PBFILE, PVFILE };

void help_message(char *error, FILE **files);
void close_files(FILE **files);
bool valid_input(char *optarg, uint64_t *variable, FILE **files);
bool check_optarg(char *optarg, FILE **files);

//
// main contains the logic that allows the parses through the flags/input and creates a public and private RSA key.
//
// main takes 2 arguments: argc and argv. argc represents the total number of command line arguments. argv represents
// every argument other than the file name/executable.
//
// main returns either 1 or 0 depending if there were any errors that occurred while running.
//
// The function below (the keygen function) is based on the ideas and instructions given in the assignment
// documentation by Professor Long.
//
int main(int argc, char **argv) {
    int8_t opt = 0;
    bool verbose = false;
    FILE *files[2] = { NULL };
    uint64_t seed = time(NULL), iterations = ITERS, bits = BITS;
    // Checks all flags
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'v': verbose = VERBOSE; break; // Stats
        case 'n': // pub file
            if (!check_optarg(optarg, files)) {
                return EXIT_FAILURE;
            }
            files[PBFILE] = fopen(optarg, "w");
            if (!files[PBFILE]) {
                help_message("Invalid file.\n", files);
                return EXIT_FAILURE;
            }
            break;
        case 'd': // priv file
            if (!check_optarg(optarg, files)) {
                return EXIT_FAILURE;
            }
            files[PVFILE] = fopen(optarg, "w");
            if (!files[PVFILE]) {
                help_message("Invalid file.\n", files);
                return EXIT_FAILURE;
            }
            break;
        case 'b': // bits for keys
            if (!check_optarg(optarg, files) || !valid_input(optarg, &bits, files)) {
                return EXIT_FAILURE;
            }
            break;
        case 'i': // iterations for prime tests
            if (!check_optarg(optarg, files) || !valid_input(optarg, &iterations, files)) {
                return EXIT_FAILURE;
            }
            break;
        case 's': // random seed
            if (!check_optarg(optarg, files) || !valid_input(optarg, &seed, files)) {
                return EXIT_FAILURE;
            }
            break;
        case 'h': help_message("", files); return EXIT_SUCCESS;
        default: help_message("Invalid flag.\n", files); return EXIT_FAILURE;
        }
    }

    if (!files[PBFILE]) {
        files[PBFILE] = fopen("rsa.pub", "w");
    }
    if (!files[PVFILE]) {
        files[PVFILE] = fopen("rsa.priv", "w");
    }
    if (!files[PVFILE] || !files[PBFILE]) {
        help_message("Error while opening a file.\n", files);
        return EXIT_FAILURE;
    }

    fchmod(fileno(files[PVFILE]), S_IRUSR | S_IWUSR); // read-only for owner
    char *username = getenv("USER");
    if (!username) {
        help_message("Unable to get username.\n", files);
        return EXIT_FAILURE;
    }

    mpz_t exponent, prime1, prime2, product, priv, name, sign;
    mpz_inits(exponent, prime1, prime2, product, priv, name, sign, NULL);
    randstate_init(seed);

    rsa_make_pub(prime1, prime2, product, exponent, bits, iterations); // Make public key
    rsa_make_priv(priv, exponent, prime1, prime2); // Make private key

    mpz_set_str(name, username, 62);
    rsa_sign(sign, name, priv, product); // User signature

    // Writes keys to corresponding files
    rsa_write_pub(product, exponent, sign, username, files[PBFILE]);
    rsa_write_priv(product, priv, files[PVFILE]);

    if (verbose) { // Verbose output
        gmp_fprintf(stdout, "User = %s\n", username);
        gmp_fprintf(stdout, "s (%d bits) = %Zd\n", mpz_sizeinbase(sign, 2), sign);
        gmp_fprintf(stdout, "p (%d bits) = %Zd\n", mpz_sizeinbase(prime1, 2), prime1);
        gmp_fprintf(stdout, "q (%d bits) = %Zd\n", mpz_sizeinbase(prime2, 2), prime2);
        gmp_fprintf(stdout, "n (%d bits) = %Zd\n", mpz_sizeinbase(product, 2), product);
        gmp_fprintf(stdout, "e (%d bits) = %Zd\n", mpz_sizeinbase(exponent, 2), exponent);
        gmp_fprintf(stdout, "d (%d bits) = %Zd\n", mpz_sizeinbase(priv, 2), priv);
    }
    close_files(files);
    randstate_clear();
    mpz_clears(exponent, prime1, prime2, product, priv, name, sign, NULL);
    return EXIT_SUCCESS;
}

//
// close_files simply closes file pointers.
//
// close_files takes 1 argument: files. Files is an array of file pointers to free.
//
// close_files returns nothing/void.
//
void close_files(FILE **files) {
    if (files[PBFILE]) {
        fclose(files[PBFILE]);
    }
    if (files[PVFILE]) {
        fclose(files[PVFILE]);
    }
}

//
// check_optarg aims to ensure a flag that needs an argument has an argument.
//
// This function takes 2 arguments: optarg and files. Files represents the files to free if there is no argument while
// optarg represents the argument to check.
//
// This function returns whether there was an argument or not.
//
bool check_optarg(char *optarg, FILE **files) {
    if (!optarg) {
        help_message("", files);
        return false;
    }
    return true;
}

//
// valid_input aims to ensure the input for certain flags are valid (no characters).
//
// This function takes 2 arguments: optarg and variables. Optarg represents the argument to check while variable
// represents the variable to set the argument to if it is valid.
//
// This function returns whether the argument was valid or not.
//
bool valid_input(char *optarg, uint64_t *variable, FILE **files) {
    // if the argument for this flag contains a character or is less than 0, print the help message
    char *invalid;
    int64_t temp_input = strtoul(optarg, &invalid, BASE10);
    if ((invalid != NULL && *invalid != '\0') || temp_input < 0) {
        help_message("Invalid argument for specified flag.\n", files);
        return false;
    }
    *variable = (uint64_t) temp_input;
    return true;
}

//
// help_message simply prints out the help message that describes how to use the program and prints an error if
// specified.
//
// Returns nothing
//
// help_message takes 2 arguments: error and files. Files represents the files to close/free and error represents the
// error to print if there is one.
//
void help_message(char *error, FILE **files) {
    if (*error != '\0') {
        fprintf(stderr, "%s", error);
    }
    close_files(files);
    fprintf(stderr,
        "SYNOPSIS\n"
        "  Generates an RSA public/private key pair.\n\n"
        "USAGE\n"
        "  ./keygen [-hv] [-i confidence] [-s seed] [-b bits] [-n pbfile] [-d pvfile]\n\n"
        "OPTIONS\n"
        "  -h              Display program help and usage.\n"
        "  -v              Display verbose program output.\n"
        "  -b bits         Minimum bits needed for the public modulus (default: 256).\n"
        "  -i confidence   Miller-Rabin iterations for testing primes (default: 50).\n"
        "  -n pbfile       Public key file (default: rsa.pub).\n"
        "  -d pvfile       Private key file (default: rsa.priv).\n"
        "  -s seed         Random seed for testing (default: seconds since the UNIX epoch)\n");
    return;
}
