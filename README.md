# Disclaimer
This repository contains a school project for <strong> cse13s </strong> and all current students should not look at the source code.

# Public Key Cryptography
The decrypt and encrypt programs aim to encrypt and/or decrypt any file type using a private and public key to prevent
everybody except the intended audience from reading the file.

The keygen program aims to generate a public and private key that allows the user to encrypt and decrypt file while
preventing others from reading the files.

Note that if the '-v' flag is specified for any of the three programs below, each program will print out verbose outputs
that may help the user understand the program output.

## Building 
The programs can be built at once using either of the commands below:
```
$ make 
```
Or 
```
$ make all
```


To build a specific program, you can simply run
```
$ make <keygen/encrypt/decrypt>
```

## Running

To run any of the three executables after compiling them, you can run the command:
```
$ ./<keygen/encrypt/decrypt> [-flag(s)]
```
OR
```
$ ./<keygen/encrypt/decrypt> [-flag] [-flag] ...
```
with any (can be multiple) flag (comand-line argument). All valid flags can be found using the '-h' flag with any executable from above.


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
