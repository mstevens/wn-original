CC=gcc
CFLAGS=-O2
#MD5LIB = ../md5/md5lib.a
MD5LIB = -lcrypto

all: suexec
suexec: suexec.c suexec.h ../config.h ../md5/md5.h
	$(CC) $(CFLAGS) -o suexec -I. suexec.c $(MD5LIB)

clean:
	rm -f suexec *~


