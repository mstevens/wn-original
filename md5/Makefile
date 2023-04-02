BINDIR=../bin
RANLIB=ranlib
CFLAGS = -Wall -I../wn 
OBJS = md5.o md5_dgst.o

all: md5 md5lib.a

md5:	$(OBJS)
	$(CC) -o md5 $(OBJS)

md5lib.a: md5_dgst.o
	ar rc md5lib.a md5_dgst.o
	@ $(RANLIB) md5lib.a


install:	md5 md5lib.a
	@-if test ! -d $(BINDIR) ; then \
		echo "Creating $(BINDIR)" ; \
		mkdir $(BINDIR) ; \
	fi
	@echo "Installing md5 in $(BINDIR)"
	@cp md5 $(BINDIR)
	@strip $(BINDIR)/md5
	@echo "Installing md5lib.a in $(BINDIR)"
	@cp md5lib.a $(BINDIR)

clean:
	rm -rf md5 md5lib.a *.o *~

md5_dgst.o: md5.h  md5_locl.h  opensslv.h
md5.o: md5.h  md5_locl.h  opensslv.h
