CC=gcc
CFLAGS=-Wall -g 
LDFLAGS=-lelf -lcrypto -lcapstone -lm
OBJ=binscan.o hash.o crypto.o incrementByFour.o
all: example binscan 

binscan: binscan.o hash.o crypto.o  
	$(CC) $(CFLAGS) -o $@ $? $(LDFLAGS)

incrementByFour.o: incrementByFour.s 
	nasm -f elf64 incrementByFour.s

%.o: %.c hash.h crypto.h
	$(CC) $(CFLAGS) -o $@ -c $< $(LDFLAGS)

.PHONY clean:
	rm -rf ./*.o mydata.bin binscan
