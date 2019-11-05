CC=gcc
CFLAGS=-Wall -g 
LDFLAGS=-lelf -lcrypto -lcapstone -lm

all: example binscan 

example: proj1_example.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

binscan: binscan.o hash.o crypto.o
	$(CC) $(CFLAGS) -o $@ $? $(LDFLAGS)

addValues: addValues.s
	nasm $<

addValues.h: addValues
	xxd -i $< > $@

%.o: %.c addValues.h hash.h crypto.h
	$(CC) $(CFLAGS) -o $@ -c $< $(LDFLAGS)

.PHONY clean:
	rm -rf ./*.o example mydata.bin addValues.h addValues binscan
