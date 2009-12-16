CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld

OPT=-O2
CFLAGS=-Wall $(XCFLAGS) $(INC) $(OPT)
LDFLAGS=-Wall $(XLDFLAGS)
LIBS=-lcrypto
THREADLIB=-lpthread
SLIBS=$(THREADLIB) $(LIBS)

EXT=

all:
	@echo 'use "make linux" for a native Linux build, or'
	@echo '    "make osx"   for a native OSX build, or'
	@echo '    "make mingw" for a MinGW32 build, or'
	@echo '    "make cygwin" for a CygWin build, or'
	@echo '    "make arm"   for a cross-compiled Linux ARM build'

progs:	rtmpdump

linux:
	@$(MAKE) $(MAKEFLAGS) progs

osx:
	@$(MAKE) XCFLAGS="-arch ppc -arch i386" $(MAKEFLAGS) progs

mingw:
	@$(MAKE) CROSS_COMPILE=mingw32- LIBS="-lws2_32 -lwinmm -lcrypto -lgdi32" THREADLIB= EXT=.exe $(MAKEFLAGS) progs

cygwin:
	@$(MAKE) XCFLAGS=-static XLDFLAGS="-static-libgcc -static" EXT=.exe $(MAKEFLAGS) progs

arm:
	@$(MAKE) CROSS_COMPILE=armv7a-angstrom-linux-gnueabi- INC=-I/OE/tmp/staging/armv7a-angstrom-linux-gnueabi/usr/include $(MAKEFLAGS) progs

clean:
	rm -f *.o rtmpdump$(EXT) streams$(EXT)

streams: bytes.o log.o rtmp.o AMFObject.o rtmppacket.o streams.o parseurl.o dh.o handshake.o
	$(CXX) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

rtmpdump: log.o rtmp.o dh.o amf.o bytes.o rtmpdump.o parseurl.o
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(LIBS)

bytes.o: bytes.c bytes.h Makefile
log.o: log.c log.h Makefile
parseurl.o: parseurl.c parseurl.h log.h Makefile
streams.o: streams.cpp rtmp.h log.h Makefile
dh.o: dh.c dh.h log.h Makefile
rtmp.o: rtmp.c rtmp.h handshake.h log.h amf.h Makefile
amf.o: amf.c amf.h Makefile
rtmpdump.o: rtmpdump.c rtmp.h log.h amf.h Makefile
