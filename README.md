# Assignment 6 - Public Key Cryptography
The decrypt and encrypt programs aim to encrypt and/or decrypt any file type using a private and public key to prevent
everybody except the intended audience from reading the file.

The keygen program aims to generate a public and private key that allows the user to encrypt and decrypt file while
preventing others from reading the files.

Note that if the '-v' flag is specified for any of the three programs below, each program will print out verbose outputs
that may help the user understand the program output.

## Citations
All functions present in the 3 programs were based off of the ideas given by Professor Long in the assignment 
documentation. Additionally, some function specifically were based off of the given pseudocode in the documentation.

## Building 
Note that the programs can be built at once using either of the commands below:
```
$ make 
```
Or 
```
$ make all
```

### Keygen:

To build the kegen program, you can run the command:
```
$ make keygen
```

### Encrypt:

To build the encrypt program, you can run the command:
```
$ make encrypt
```

### Decrypt:

To build the decrypt program, you can run the command:
```
$ make decrypt
```

## Running

### Keygen:

To run the keygen program after compiling it, you can run the command:
```
$ ./keygen -<flag(s)>
```
OR
```
$ ./keygen -<flag> -<flag> ...
```
with any (can be multiple) flag (comand-line argument) below:


|Flag                  |Output                                                                                      | 
|:--------------------:| ------------------------------------------------------------------------------------------ |
|-v                    |Prints statistics that represent the aspects of both keys (private and public).   |
|-b <em> bits </em> |Specifies the minimum bits needed for the public modulus. Default: 256                      |
|-n <em> pubkey </em> |Specifies an outfile file path for the public key. Default: rsa.pub                      |
|-d <em> privkey </em> |Specifies an outfile file path for the private key. Default: rsa.priv                      |
|-i <em> confidence </em> |Specifies the number of Miller-Rabin iterations for testing primes. Default: 50                      |
|-s <em> seed </em> |Specifies the random seed for the random state initialization. Default: seconds since the UNIX epoch|
|-h                    |Displays a help message detailing how to use the program.                                   |

Note that to enter an argument for the flags that require arguments, you can simply add the argument after the flag with
a space in between, as shown below:
```
$ ./keygen -n ~/path/to/pubkey/file
```


### Encrypt:

To run the encrypt program after compiling it, you can run the command:
```
$ ./encrypt -<flag(s)>
```
OR
```
$ ./encrypt -<flag> -<flag> ...
```
with any (can be multiple) flag (comand-line argument) below:


|Flag                  |Output                                                                                      | 
|:--------------------:| ------------------------------------------------------------------------------------------ |
|-v                    |Prints statistics that represent the aspects of the public key.   |
|-i <em> infile </em>  |Specifies an input file path representing the file to encrypt. Default: stdin  |
|-o <em> outfile </em> |Specifies an outfile file path to print the encrypted file to. Default: stdout                      |
|-n <em> pubkey </em> |Specifies a file path containing the public key. Default: rsa.pub                      |
|-h                    |Displays a help message detailing how to use the program.                                   |

Note that to enter an argument for the flags that require arguments, you can simply add the argument after the flag with
a space in between, as shown below:
```
$ ./encrypt -o ~/path/to/outfile
```

### Decrypt:

To run the decrypt program after compiling it, you can run the command:
```
$ ./decrypt -<flag(s)>
```
OR
```
$ ./decrypt -<flag> -<flag> ...
```
with any (can be multiple) flag (comand-line argument) below:


|Flag                  |Output                                                                                      | 
|:--------------------:| ------------------------------------------------------------------------------------------ |
|-v                    |Prints statistics that represent the aspects of the private key.   |
|-i <em> infile </em>  |Specifies an input file path representing the file to decrypt. Default: stdin  |
|-o <em> outfile </em> |Specifies an outfile file path to print the decrypted file to. Default: stdout                      |
|-n <em> privkey </em> |Specifies a file path containing the private key. Default: rsa.priv                      |
|-h                    |Displays a help message detailing how to use the program.                                   |

Note that to enter an argument for the flags that require arguments, you can simply add the argument after the flag with
a space in between, as shown below:
```
$ ./decrypt -o ~/path/to/outfile
```

### Example:
Running the command below after building the program will encode and \
decode a text file.
```
$ cat file.txt
$
$ ./keygen -s 445
$ cat rsa.pub
$
$ ./encrypt -i file.txt -o output
$ ./decrypt -i output
$
```
\
Result from the example above:
```
> Hello World!!!
>
>
> 25eb9f24bd32e5683d17dd6dab2d7672f79ddf43aa40c6c85aed5e75979b5b26d
> 734ca7ab4ee1c7b507b24686ced92c4ba112b0e228a4f6eb607b8eebd7f7474b
> 2c4e24777717476655de1594652ab2ec3d5ed757871f9a81b335c293d0e537c
> ejpoon
>
> Hello World!!!
```

## False positive bugs via scan-build
There is one false positive bug in the rsa\_encrypt\_file function where it notes that we may get an error when setting
the first index of block to 0xFF when we are either unable to allocate memory or the size is less than 1. This is a
valid note, bit my implementation has conditionals that ensure we can allocate memory for an array that is at least of
size 1. If it isn't, the function call will end.

Note that I included a slight fix to the program to avoid the scan-builc false positive by simply adding one to the size
of the calloc call to ensure the size is guaranteed to be at least 1. This will not affect the outcome of the function
because if the 1 is needed to keep the array size 1, then a previous conditional check would have caught it.
Additionally, the future lines will never use that extra +1 index.
