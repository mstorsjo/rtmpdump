CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld

DEF=-DRTMPDUMP_VERSION=\"v2.2\"
OPT=-O2
CFLAGS=-Wall $(XCFLAGS) $(INC) $(DEF) $(OPT)
LDFLAGS=-Wall $(XLDFLAGS)
LIBS=-lcrypto -lz
THREADLIB=-lpthread
LIBRTMP=librtmp/librtmp.a
SLIBS=$(THREADLIB) $(LIBS)

EXT=

all:
	@echo 'use "make posix" for a native Linux/Unix build, or'
	@echo '    "make mingw" for a MinGW32 build'
	@echo 'use commandline overrides if you want anything else'

progs:	rtmpdump rtmpgw rtmpsrv rtmpsuck

posix linux unix osx:
	@$(MAKE) $(MAKEFLAGS) progs

mingw:
	@$(MAKE) CROSS_COMPILE=mingw32- LIBS="$(LIBS) -lws2_32 -lwinmm -lgdi32" THREADLIB= EXT=.exe $(MAKEFLAGS) progs

cygwin:
	@$(MAKE) XCFLAGS=-static XLDFLAGS="-static-libgcc -static" EXT=.exe $(MAKEFLAGS) progs

cross:
	@$(MAKE) CROSS_COMPILE=armv7a-angstrom-linux-gnueabi- INC=-I/OE/tmp/staging/armv7a-angstrom-linux-gnueabi/usr/include $(MAKEFLAGS) progs

clean:
	rm -f *.o rtmpdump$(EXT) rtmpgw$(EXT) rtmpsrv$(EXT) rtmpsuck$(EXT)
	@$(MAKE) -C librtmp clean

$(LIBRTMP):
	@$(MAKE) -C librtmp all CC="$(CC)" CFLAGS="$(CFLAGS)"

rtmpdump: rtmpdump.o parseurl.o $(LIBRTMP)
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(LIBS)

rtmpsrv: rtmpsrv.o thread.o $(LIBRTMP)
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

rtmpsuck: rtmpsuck.o thread.o $(LIBRTMP)
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

rtmpgw: rtmpgw.o parseurl.o thread.o $(LIBRTMP)
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

parseurl.o: parseurl.c parseurl.h Makefile
rtmpgw.o: rtmpgw.c librtmp/rtmp.h librtmp/log.h librtmp/amf.h Makefile
rtmpdump.o: rtmpdump.c librtmp/rtmp.h librtmp/log.h librtmp/amf.h Makefile
rtmpsrv.o: rtmpsrv.c librtmp/rtmp.h librtmp/log.h librtmp/amf.h Makefile
thread.o: thread.c thread.h
