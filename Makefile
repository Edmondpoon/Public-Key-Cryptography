CC = clang
CFLAGS = -Wall -Wpedantic -Werror -Wextra $(shell pkg-config --cflags gmp)
LFLAGS = $(shell pkg-config --libs gmp)

RSA = ./src/rsa/
SRC = ./src/
OBJS = $(RSA)rsa.o $(RSA)randstate.o $(RSA)numtheory.o
KEYGEN = $(SRC)keygen.o
ENCRYPT = $(SRC)encrypt.o
DECRYPT = $(SRC)decrypt.o

.PHONY: all clean scan-build debug keys

all: keygen encrypt decrypt

keygen: $(OBJS) $(KEYGEN)
	$(CC) -o $@ $(OBJS) $(KEYGEN) $(LFLAGS)

encrypt: $(OBJS) $(ENCRYPT)
	$(CC) -o $@ $(OBJS) $(ENCRYPT) $(LFLAGS)

decrypt: $(OBJS) $(DECRYPT)
	$(CC) -o $@ $(OBJS) $(DECRYPT) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

keys: clean
	rm -f rsa.p*

clean:
	rm -f keygen encrypt decrypt *.o

scan-build: clean
	scan-build --use-cc=$(CC) make	

debug: CFLAGS += -g
debug: clean all
