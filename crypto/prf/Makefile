#
# OpenSSL/crypto/md/Makefile
#

DIR=	prf
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=prftest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=prf_derive.c prf_pmeth.c
LIBOBJ=prf_derive.o prf_pmeth.o

SRC= $(LIBSRC)

EXHEADER= prf.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

prf_derive.o: ../../e_os.h ../../include/openssl/asn1.h
prf_derive.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
prf_derive.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
prf_derive.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
prf_derive.o: ../../include/openssl/dtls1.h ../../include/openssl/e_os2.h
prf_derive.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
prf_derive.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
prf_derive.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
prf_derive.o: ../../include/openssl/kssl.h ../../include/openssl/lhash.h
prf_derive.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
prf_derive.o: ../../include/openssl/opensslconf.h
prf_derive.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
prf_derive.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
prf_derive.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
prf_derive.o: ../../include/openssl/prf.h ../../include/openssl/rsa.h
prf_derive.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
prf_derive.o: ../../include/openssl/srtp.h ../../include/openssl/ssl.h
prf_derive.o: ../../include/openssl/ssl2.h ../../include/openssl/ssl23.h
prf_derive.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
prf_derive.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
prf_derive.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
prf_derive.o: ../../ssl/ssl_locl.h ../cryptlib.h prf_derive.c
prf_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
prf_pmeth.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
prf_pmeth.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
prf_pmeth.o: ../../include/openssl/cms.h ../../include/openssl/crypto.h
prf_pmeth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
prf_pmeth.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
prf_pmeth.o: ../../include/openssl/err.h ../../include/openssl/evp.h
prf_pmeth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
prf_pmeth.o: ../../include/openssl/objects.h
prf_pmeth.o: ../../include/openssl/opensslconf.h
prf_pmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
prf_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/pool.h
prf_pmeth.o: ../../include/openssl/prf.h ../../include/openssl/safestack.h
prf_pmeth.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
prf_pmeth.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
prf_pmeth.o: ../../include/openssl/x509_vfy.h ../cryptlib.h ../evp/evp_locl.h
prf_pmeth.o: prf_pmeth.c
