CC = cc

BINDIR = ../bin

# Uncomment these two lines to use the DBM features of wndigest
# You will likely have to change DBMLIB to whatever library contains
# the DBM functions dbm_open(), dbm_fetch() and dbm_close() on your system.
# Typically this is -lndbm or -ldbm.

#DBMLIB = -lndbm
#DBMFLAG =  -DDBM_AUTH

CFLAGS = -I../wn/ -DMD=5 $(DBMFLAG)

OBJS = wndigest.o md5c.o

all:	md5 wndigest

wndigest: $(OBJS)
	$(CC) $(CFLAGS) -o wndigest $(OBJS) $(LIBS) $(DBMLIB)

md5: mddriver.o md5c.o
	$(CC) $(CFLAGS) -o md5 mddriver.o md5c.o $(LIBS)

install:	wndigest md5
	@-if test ! -d $(BINDIR) ; then \
		echo "Creating $(BINDIR)" ; \
		mkdir $(BINDIR) ; \
	fi
	@echo "Installing wndigest and md5 in $(BINDIR)"
	@cp wndigest $(BINDIR)
	@strip $(BINDIR)/wndigest
	@cp md5 $(BINDIR)
	@strip $(BINDIR)/md5

clean:
	rm -f *.o  *~ wndigest md5

wndigest.o:	md5 wndigest.c wndigest.h global.h md5.h ../config.h
	@echo "Calculating random seed"
	perl ./rand > random.h
	$(CC) $(CFLAGS) -c wndigest.c -o wndigest.o
	rm -f random.h

md5c.o: md5c.c global.h md5.h
mddriver.o: mddriver.c md5c.c global.h md5.h
wndigest.o: md5c.c wndigest.c wndigest.h



