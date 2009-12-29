CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld

OPT=-O2
CFLAGS=-Wall $(XCFLAGS) $(INC) $(OPT)
LDFLAGS=-Wall $(XLDFLAGS)
LIBS=-lcrypto -lcurl -lz
THREADLIB=-lpthread
SLIBS=$(THREADLIB) $(LIBS)

EXT=

all:
	@echo 'use "make linux" for a native Linux build, or'
	@echo '    "make osx"   for a native OSX build, or'
	@echo '    "make mingw" for a MinGW32 build, or'
	@echo '    "make cygwin" for a CygWin build, or'
	@echo '    "make arm"   for a cross-compiled Linux ARM build'

progs:	rtmpdump streams

linux:
	@$(MAKE) $(MAKEFLAGS) progs

osx:
	@$(MAKE) XCFLAGS="-arch ppc -arch i386" $(MAKEFLAGS) progs

mingw:
	@$(MAKE) CROSS_COMPILE=mingw32- LIBS="-lws2_32 -lwinmm -lgdi32 $(LIBS)" THREADLIB= EXT=.exe $(MAKEFLAGS) progs

cygwin:
	@$(MAKE) XCFLAGS=-static XLDFLAGS="-static-libgcc -static" EXT=.exe $(MAKEFLAGS) progs

arm:
	@$(MAKE) CROSS_COMPILE=armv7a-angstrom-linux-gnueabi- INC=-I/OE/tmp/staging/armv7a-angstrom-linux-gnueabi/usr/include $(MAKEFLAGS) progs

clean:
	rm -f *.o rtmpdump$(EXT) streams$(EXT)

streams: log.o rtmp.o amf.o streams.o parseurl.o swfvfy.o
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

rtmpdump: log.o rtmp.o amf.o rtmpdump.o parseurl.o swfvfy.o
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(LIBS)

rtmpsrv: log.o rtmp.o amf.o rtmpsrv.o
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

rtmpsuck: log.o rtmp.o amf.o rtmpsuck.o swfvfy.o
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

log.o: log.c log.h Makefile
parseurl.o: parseurl.c parseurl.h log.h Makefile
streams.o: streams.c rtmp.h log.h swfvfy.o Makefile
rtmp.o: rtmp.c rtmp.h handshake.h dh.h log.h amf.h Makefile
amf.o: amf.c amf.h bytes.h log.h Makefile
rtmpdump.o: rtmpdump.c rtmp.h log.h amf.h Makefile
rtmpsrv.o: rtmpsrv.c rtmp.h log.h amf.h Makefile
swfvfy.o: swfvfy.c
