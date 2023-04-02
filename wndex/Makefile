BINDIR=../bin
RANLIB=ranlib
CFLAGS = -I.. -I../wn -Wall
MD5LIB = ../md5/md5lib.a
#MD5LIB = -lcrypto

OBJS	= wndex.o init.o content.o serveall.o base64.o

all:	wndex

wndex: $(OBJS)
	$(CC) $(CFLAGS) -o wndex $(OBJS) $(MD5LIB) $(LIBS)

install:	wndex
	@-if test ! -d $(BINDIR) ; then \
		echo "Creating $(BINDIR)" ; \
		mkdir $(BINDIR) ; \
	fi
	@echo "Installing wndex in $(BINDIR)"
	@cp wndex $(BINDIR)
	@strip $(BINDIR)/wndex

clean:
	@rm -f *.o *.a  *~ wndex

wndex.o: 	wndex.h err.h ../wn/common.h ../config.h
init.o: 	wndex.h err.h ../wn/common.h ../config.h ../wn/version.h
content.o: 	wndex.h err.h ../wn/common.h ../config.h \
		 ../wn/content.h
serveall.o: 	wndex.h err.h ../wn/common.h ../config.h
base64.o:	../md5/md5.h
