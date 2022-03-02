#include "numtheory.h"
#include "rsa.h"
#include "randstate.h"
#include <unistd.h>
#include <stdlib.h>

#define OPTIONS "i:o:n:vh"
#define VERBOSE true

enum Files { INFILE, OUTFILE, PVFILE };

void help_message(char *error, FILE **files);
void close_files(FILE **files);
bool check_optarg(char *optarg, FILE **files);


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
        case 'n': // Private file
            if (!check_optarg(optarg, files)) {
                return EXIT_FAILURE;
            }
            files[PVFILE] = fopen(optarg, "r");
            if (!files[PVFILE]) {
                help_message("Invalid file.\n", files);
                return EXIT_FAILURE;
            }
            break;
        case 'h': help_message("", files); return EXIT_SUCCESS;
        default: help_message("Invalid flag.\n", files); return EXIT_FAILURE;
        }
    }

    if (!files[PVFILE]) {
        files[PVFILE] = fopen("rsa.priv", "r");
    }
    if (!files[PVFILE]) {
        help_message("Unable to open rsa.priv\n", files);
        return EXIT_FAILURE;
    }

    mpz_t secret, mod;
    mpz_inits(secret, mod, NULL);
    rsa_read_priv(mod, secret, files[PVFILE]); // Read provate key and public modulus
    if (verbose) { // Verbose output
        gmp_fprintf(stdout, "n (%d bits) = %Zd\n", mpz_sizeinbase(mod, 2), mod);
        gmp_fprintf(stdout, "d (%d bits) = %Zd\n", mpz_sizeinbase(secret, 2), secret);
    }
    rsa_decrypt_file(files[INFILE], files[OUTFILE], mod, secret);
    close_files(files);
    mpz_clears(secret, mod, NULL);
    return EXIT_SUCCESS;
}

//
// Closes file pointers.
//
// files: an array of file pointers
//
void close_files(FILE **files) {
    if (files[PVFILE]) {
        fclose(files[PVFILE]);
    }
    if (files[INFILE] && files[INFILE] != stdin) {
        fclose(files[INFILE]);
    }
    if (files[OUTFILE] && files[OUTFILE] != stdout) {
        fclose(files[OUTFILE]);
    }
    return;
}

//
// Ensures a flag that needs an argument has an argument.
//
// optarg: the argument given to the specific flag
// files: an array of file pointers
//
bool check_optarg(char *optarg, FILE **files) {
    if (!optarg) {
        help_message("", files);
        return false;
    }
    return true;
}

//
// Prints out the help message that describes how to use the program and prints an error if specified.
//
// error: the error to print
// files: an array of file pointers
//
void help_message(char *error, FILE **files) {
    if (*error != '\0') {
        fprintf(stderr, "%s", error);
    }
    close_files(files);
    fprintf(stderr, "SYNOPSIS\n"
                    "  Decrypts data using RSA encryption.\n"
                    "  Encrypted data is encrypted by the encrypt program.\n\n"
                    "USAGE\n"
                    "  ./decrypt [-hv] [-i infile] [-o outfile] [-d privkey]\n\n"
                    "OPTIONS\n"
                    "  -h              Display program help and usage.\n"
                    "  -v              Display verbose program output.\n"
                    "  -i infile       Input file of data to decrypt (default: stdin).\n"
                    "  -o outfile      Output file for decrypted data (default: stdout).\n"
                    "  -n pvfile       Private key file (default: rsa.priv).\n");
    return;
}
