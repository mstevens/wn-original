#CC = gcc

#Uncomment these two lines to use the DBM features of wnauth
#You will likely have to change DBMLIB to whatever library contains
# the NDBM functions dbm_open(), dbm_fetch() and dbm_close() on your system.
# Typically this is -lndbm or -ldbm.

#DBMLIB = -lndbm
#DBMFLAG =  -DDBM_AUTH
BINDIR=../bin
LIBS = -lcrypt
PAMLIBS = -lpam
#MD5LIB = ../md5/md5lib.a
MD5LIB= -lcrypto

CFLAGS = -I../wn -I../md5 $(DBMFLAG) -Wall

OBJS = wnauth.o
PAMOBJS = wn_pamauth.o


all:	wnauth

wnauth: $(OBJS)
	-$(CC) $(CFLAGS) -o wnauth $(OBJS) $(LIBS) $(MD5LIB) $(DBMLIB)

wn_pamauth: $(PAMOBJS)
	$(LD) -x  --shared  -o  wn_pamauth.so  wn_pamauth.o $(LIBS) $(MD5LIB) $(PAMLIBS)

wn_pamauth.o : wnauth.h wn_pamauth.c ../config.h
	$(CC) $(CFLAGS) -fPIC -c wn_pamauth.c 

install:	wnauth
	@-if test ! -d $(BINDIR) ; then \
		echo "Creating $(BINDIR)" ; \
		mkdir $(BINDIR) ; \
	fi
	@echo "Installing wnauth in $(BINDIR)"
	@-cp wnauth $(BINDIR)
	@-strip $(BINDIR)/wnauth
	@echo "Installing wn_md5passwd in $(BINDIR)"
	@-chmod +x wn_md5passwd
	@-cp wn_md5passwd $(BINDIR)
	@-if test -x wn_pamauth.so ; then \
		echo "Installing wn_pamauth.so in $(BINDIR)" ; \
		cp wn_pamauth.so $(BINDIR) ; \
	fi
clean:
	@rm -f *.o  *~ wnauth wn_pamauth.so

wnauth.o: 		wnauth.h  ../config.h

