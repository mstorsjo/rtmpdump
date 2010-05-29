VERSION=v2.2e

prefix=/usr/local

CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
AR=$(CROSS_COMPILE)ar

CRYPTO=OPENSSL
#CRYPTO=GNUTLS
DEF_POLARSSL=-DUSE_POLARSSL
DEF_OPENSSL=-DUSE_OPENSSL
DEF_GNUTLS=-DUSE_GNUTLS
DEF_=-DNO_CRYPTO
REQ_GNUTLS=gnutls
REQ_OPENSSL=libssl,libcrypto
CRYPTO_REQ=$(REQ_$(CRYPTO))
CRYPTO_DEF=$(DEF_$(CRYPTO))

DEF=-DRTMPDUMP_VERSION=\"$(VERSION)\" $(CRYPTO_DEF) $(XDEF)
OPT=-O2
CFLAGS=-Wall $(XCFLAGS) $(INC) $(DEF) $(OPT)

incdir=$(prefix)/include/librtmp
libdir=$(prefix)/lib
mandir=$(prefix)/man
INCDIR=$(DESTDIR)$(incdir)
LIBDIR=$(DESTDIR)$(libdir)
MANDIR=$(DESTDIR)$(mandir)

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
		-e "s;@CRYPTO_REQ@;$(CRYPTO_REQ);" librtmp.pc.in > $@

install:	librtmp.a librtmp.pc
	-mkdir -p $(INCDIR) $(LIBDIR)/pkgconfig $(MANDIR)/man3
	cp amf.h http.h log.h rtmp.h $(INCDIR)
	cp librtmp.a $(LIBDIR)
	cp librtmp.pc $(LIBDIR)/pkgconfig
	cp librtmp.3 $(MANDIR)/man3
