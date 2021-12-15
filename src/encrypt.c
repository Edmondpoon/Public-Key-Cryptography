#include "numtheory.h"
#include "rsa.h"
#include "randstate.h"
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#define OPTIONS "i:o:n:vh"
#define VERBOSE true

enum Files { INFILE, OUTFILE, PBFILE };

void help_message(char *error, FILE **files);
void close_files(FILE **files);
bool check_optarg(char *optarg, FILE **files);

//
// main contains the logic that allows the parses through the flags/input and outputs a encrypted file.
//
// main takes 2 arguments: argc and argv. argc represents the total number of command line arguments. argv represents
// every argument other than the file name/executable.
//
// main returns either 1 or 0 depending if there were any errors that occurred while running.
//
// The function below (the encrypt function) is based on the ideas and instructions given in the assignment
// documentation by Professor Long.
//
int main(int argc, char **argv) {
    int8_t opt = 0;
    bool verbose = false;
    FILE *files[3] = { stdin, stdout, NULL };
    // Checks all flags
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'v': verbose = VERBOSE; break; // Stats
        case 'i': // Input
            if (!check_optarg(optarg, files)) {
                return EXIT_FAILURE;
            }
            files[INFILE] = fopen(optarg, "r");
            if (!files[INFILE]) {
                help_message("Invalid file.\n", files);
                return EXIT_FAILURE;
            }
            break;
        case 'o': // Output
            if (!check_optarg(optarg, files)) {
                return EXIT_FAILURE;
            }
            files[OUTFILE] = fopen(optarg, "w");
            if (!files[OUTFILE]) {
                help_message("Invalid file.\n", files);
                return EXIT_FAILURE;
            }
            break;
        case 'n': // Public key
            if (!check_optarg(optarg, files)) {
                return EXIT_FAILURE;
            }
            files[PBFILE] = fopen(optarg, "r");
            if (!files[PBFILE]) {
                help_message("Invalid file.\n", files);
                return EXIT_FAILURE;
            }
            break;
        case 'h': help_message("", files); return EXIT_SUCCESS;
        default: help_message("Invalid flag.\n", files); return EXIT_FAILURE;
        }
    }

    if (!files[PBFILE]) {
        files[PBFILE] = fopen("rsa.pub", "r");
    }
    if (!files[PBFILE]) {
        help_message("Unable to open rsa.pub\n", files);
        return EXIT_FAILURE;
    }

    char user[1024];
    mpz_t sign, exponent, mod, verify;
    mpz_inits(sign, exponent, mod, verify, NULL);
    rsa_read_pub(mod, exponent, sign, user,
        files[PBFILE]); // Reads in public key, exponent, and user signature/username

    if (verbose) { // Verbose output
        gmp_fprintf(stdout, "User = %s\n", user);
        gmp_fprintf(stdout, "s (%d bits) = %Zd\n", mpz_sizeinbase(sign, 2), sign);
        gmp_fprintf(stdout, "n (%d bits) = %Zd\n", mpz_sizeinbase(mod, 2), mod);
        gmp_fprintf(stdout, "e (%d bits) = %Zd\n", mpz_sizeinbase(exponent, 2), exponent);
    }

    if (mpz_set_str(verify, user, 62)) { // Verify sender user
        mpz_clears(exponent, mod, verify, sign, NULL);
        close_files(files);
        return EXIT_FAILURE;
    }
    if (!rsa_verify(verify, sign, exponent, mod)) {
        fprintf(stderr, "Invalid signature!\n");
        mpz_clears(exponent, mod, verify, sign, NULL);
        close_files(files);
        return EXIT_FAILURE;
    }
    rsa_encrypt_file(files[INFILE], files[OUTFILE], mod, exponent);
    close_files(files);
    mpz_clears(exponent, mod, verify, sign, NULL);
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
    if (files[INFILE] && files[INFILE] != stdin) {
        fclose(files[INFILE]);
    }
    if (files[OUTFILE] && files[OUTFILE] != stdout) {
        fclose(files[OUTFILE]);
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
    fprintf(stderr, "SYNOPSIS\n"
                    "  Encrypts data using RSA encryption.\n"
                    "  Encrypted data is decrypted by the decrypt program.\n\n"
                    "USAGE\n"
                    "  ./encrypt [-hv] [-i infile] [-o outfile] [-n pubkey]\n\n"
                    "OPTIONS\n"
                    "  -h              Display program help and usage.\n"
                    "  -v              Display verbose program output.\n"
                    "  -i infile       Input file of data to encrypt (default: stdin).\n"
                    "  -o outfile      Output file for encrypted data (default: stdout).\n"
                    "  -n pbfile       Public key file (default: rsa.pub).\n");
    return;
}
