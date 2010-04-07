VERSION=v2.2b

prefix=/usr/local

CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld

CRYPTO=OPENSSL
#CRYPTO=GNUTLS
DEF_OPENSSL=-DCRYPTO -DUSE_OPENSSL
DEF_GNUTLS=-DCRYPTO -DUSE_GNUTLS
LIB_GNUTLS=-lgnutls
LIB_OPENSSL=-lssl -lcrypto
REQ_GNUTLS=gnutls
REQ_OPENSSL=libssl,libcrypto
CRYPTO_LIB=$(LIB_$(CRYPTO))
CRYPTO_REQ=$(REQ_$(CRYPTO))
CRYPTO_DEF=$(DEF_$(CRYPTO))

DEF=-DRTMPDUMP_VERSION=\"$(VERSION)\" $(CRYPTO_DEF)
OPT=-O2
CFLAGS=-Wall $(XCFLAGS) $(INC) $(DEF) $(OPT)

INCDIR=$(DESTDIR)$(prefix)/include/librtmp

all:	librtmp.a

clean:
	rm -f *.o *.a

librtmp.a: rtmp.o log.o amf.o hashswf.o parseurl.o
	$(AR) rs $@ $?

log.o: log.c log.h Makefile
rtmp.o: rtmp.c rtmp.h rtmp_sys.h handshake.h dh.h log.h amf.h Makefile
amf.o: amf.c amf.h bytes.h log.h Makefile
hashswf.o: hashswf.c http.h rtmp.h rtmp_sys.h Makefile
parseurl.o: parseurl.c rtmp.h rtmp_sys.h log.h Makefile

librtmp.pc: librtmp.pc.in Makefile
	sed -e "s;@prefix@;$(prefix);" -e "s;@VERSION@;$(VERSION);" \
		-e "s;@CRYPTO_LIB@;$(CRYPTO_LIB);" -e "s;@CRYPTO_REQ@;$(CRYPTO_REQ);" \
		librtmp.pc.in > $@

install:	librtmp.a librtmp.pc
	-mkdir -p $(INCDIR) $(DESTDIR)$(prefix)/lib/pkgconfig
	cp amf.h http.h log.h rtmp.h $(INCDIR)
	cp librtmp.a $(DESTDIR)$(prefix)/lib
	cp librtmp.pc $(DESTDIR)$(prefix)/lib/pkgconfig
