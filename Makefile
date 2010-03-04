CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld

DEF=-DRTMPDUMP_VERSION=\"v2.1d\"
OPT=-O2
CFLAGS=-Wall $(XCFLAGS) $(INC) $(DEF) $(OPT)
LDFLAGS=-Wall $(XLDFLAGS)
LIBS=-lcrypto -lz
THREADLIB=-lpthread
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
	rm -f *.o *.a rtmpdump$(EXT) rtmpgw$(EXT) rtmpsrv$(EXT) rtmpsuck$(EXT)

librtmp.a: rtmp.o log.o amf.o hashswf.o
	$(AR) rs $@ $?

rtmpdump: rtmpdump.o parseurl.o librtmp.a
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(LIBS)

rtmpsrv: rtmpsrv.o thread.o librtmp.a
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

rtmpsuck: rtmpsuck.o thread.o librtmp.a
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

rtmpgw: rtmpgw.o parseurl.o thread.o librtmp.a
	$(CC) $(LDFLAGS) $^ -o $@$(EXT) $(SLIBS)

log.o: log.c log.h Makefile
parseurl.o: parseurl.c parseurl.h log.h Makefile
rtmpgw.o: rtmpgw.c rtmp.h log.h hashswf.o Makefile
rtmp.o: rtmp.c rtmp.h handshake.h dh.h log.h amf.h Makefile
amf.o: amf.c amf.h bytes.h log.h Makefile
rtmpdump.o: rtmpdump.c rtmp.h log.h amf.h Makefile
rtmpsrv.o: rtmpsrv.c rtmp.h log.h amf.h Makefile
hashswf.o: hashswf.c http.h
thread.o: thread.c thread.h
