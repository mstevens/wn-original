#CC = gcc

BINDIR=../bin

CFLAGS = -I../wn/ -O -Wall

OBJS = puth.o

all:	wnputh

wnputh: $(OBJS)
	-$(CC) $(CFLAGS) -o wnputh $(OBJS) $(LIBS)

install:	wnputh
	@-if test ! -d $(BINDIR) ; then \
		echo "Creating $(BINDIR)" ; \
		mkdir $(BINDIR) ; \
	fi
	@echo "Installing wnputh in $(BINDIR)"
	@-cp wnputh $(BINDIR)
	@-strip $(BINDIR)/wnputh

clean:
	@rm -f *.o  *~ wnputh

puth.o:	puth.h  ../config.h

