CC = clang
CFLAGS = -Wall -Wpedantic -Werror -Wextra $(shell pkg-config --cflags gmp)
OBJS = rsa.o randstate.o numtheory.o
LFLAGS = $(shell pkg-config --libs gmp)
KEYGEN = keygen.o
ENCRYPT = encrypt.o
DECRYPT = decrypt.o

.PHONY: all clean format scan-build debug keys

all: keygen encrypt decrypt

keygen: $(OBJS) $(KEYGEN)
	$(CC) -o $@ $(OBJS) $(KEYGEN) $(LFLAGS)

encrypt: $(OBJS) $(ENCRYPT)
	$(CC) -o $@ $(OBJS) $(ENCRYPT) $(LFLAGS)

decrypt: $(OBJS) $(DECRYPT)
	$(CC) -o $@ $(OBJS) $(DECRYPT) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f keygen encrypt decrypt *.o

format:
	clang-format -i -style=file *.[ch]

scan-build: clean
	scan-build --use-cc=$(CC) make	

debug: CFLAGS += -g
debug: clean all

keys: clean
	rm -f rsa.p*
