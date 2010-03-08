CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld

DEF=-DRTMPDUMP_VERSION=\"v2.2\"
OPT=-O2
CFLAGS=-Wall $(XCFLAGS) $(INC) $(DEF) $(OPT)

all:	librtmp.a

clean:
	rm -f *.o *.a

librtmp.a: rtmp.o log.o amf.o hashswf.o parseurl.o
	$(AR) rs $@ $?

log.o: log.c log.h Makefile
rtmp.o: rtmp.c rtmp.h handshake.h dh.h log.h amf.h Makefile
amf.o: amf.c amf.h bytes.h log.h Makefile
hashswf.o: hashswf.c http.h
parseurl.o: parseurl.c
