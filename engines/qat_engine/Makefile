ifndef CMN_ROOT
CRYPTO_MEMORY_DRIVER=qat_mem
else
CRYPTO_MEMORY_DRIVER=qae_mem
endif

DIR=qat_engine
TOP=../..
CC=cc
INCLUDES= -I../../include 
CFLAG=-g
ifeq ($(MAKEFILE),)
MAKEFILE:= Makefile
endif
AR= ar r
CFLAGS+= $(INCLUDES) $(CFLAG)

ifeq ($(CRYPTO_MEMORY_DRIVER),qat_mem)
CFLAGS+=-D USE_QAT_MEM -Iqat_mem
endif
ifeq ($(CRYPTO_MEMORY_DRIVER),qae_mem)
CFLAGS+=-D USE_QAE_MEM
INCLUDES+= -I./
INCLUDES+= -I$(CMN_ROOT)
endif

# Include path for Intel QAT API
ICP_API_DIR = ${ICP_ROOT}/quickassist/include
ICP_SAL_API_DIR = $(ICP_ROOT)/quickassist/lookaside/access_layer/include

ifdef ICP_API_PATH
ICP_API_DIR = $(ICP_API_PATH)
endif

ifdef ICP_SAL_API_PATH 
ICP_SAL_API_DIR = $(ICP_SAL_API_PATH)
endif
ICP_LAC_API_DIR = $(ICP_API_DIR)/lac

INCLUDES += -I$(ICP_API_DIR) -I$(ICP_LAC_API_DIR) -I$(ICP_SAL_API_DIR) -I$(TOP)/crypto/ecdh -I$(TOP)/crypto/ecdsa -I$(TOP)/crypto/evp
DRIVER=icp_qa_al
ifdef WITH_CPA_MUX
ICP_MUX_DIR=$(ICP_ROOT)/../QAT1.5/quickassist/include
ICP_DC_DIR=$(ICP_API_DIR)/dc
CFLAGS += -DWITH_CPA_MUX
INCLUDES += -I$(ICP_MUX_DIR) -I$(ICP_DC_DIR)
DRIVER=qat_mux
endif

QATLIBSRC_SHARED = e_qat.c\
	 qat_utils.c\
	 qat_ciphers.c\
	 qat_chain.c\
	 qat_digests.c\
	 qat_rsa.c\
	 qat_dsa.c\
	 qat_dh.c\
         qat_ecdh.c\
         qat_ecdsa.c\
	 qat_asym_common.c\
	 qat_sym_common.c\
	 e_qat_err.c\
	 qat_parseconf.c\
	 qat_rand.c\
	 qat_prf.c

QATLIBOBJ_SHARED = e_qat.o \
qat_utils.o \
qat_ciphers.o \
qat_chain.o \
qat_digests.o \
qat_rsa.o \
qat_dsa.o \
qat_dh.o \
qat_ecdh.o \
qat_ecdsa.o \
qat_asym_common.o \
qat_sym_common.o \
e_qat_err.o \
qat_parseconf.o \
qat_rand.o \
qat_prf.o

ifeq ($(CRYPTO_MEMORY_DRIVER),qat_mem)
QATLIBSRC = $(QATLIBSRC_SHARED)  qae_mem_utils.c 
QATLIBOBJ = $(QATLIBOBJ_SHARED)  qae_mem_utils.o 
QATLIBMEMOBJ = qae_mem_utils.o 
QATLIBMEM =qae_mem_utils
QATLIBMEMDEPS=
endif
ifeq ($(CRYPTO_MEMORY_DRIVER),qae_mem)
QATLIBSRC = $(QATLIBSRC_SHARED) qat_mem_drv_inf.c 
QATLIBOBJ = $(QATLIBOBJ_SHARED) qat_mem_drv_inf.o 
QATLIBMEMOBJ = qat_mem_drv_inf.o 
QATLIBMEM = qat_mem_drv_inf
QATLIBMEMDEPS=
endif

SRC=$(QATLIBSRC)
QATLIBTARGET=$(TOP)/libcrypto.a
ifdef ICP_BUILD_OUTPUT
QATSHAREDLIBDEPS=-Wl,-rpath,$(ICP_BUILD_OUTPUT) -L$(ICP_BUILD_OUTPUT) -l$(DRIVER)_s
else
QATSHAREDLIBDEPS=-l$(DRIVER)_s
endif

ifeq ($(CRYPTO_MEMORY_DRIVER),qat_mem)
QATSHAREDLIBDEPS += -L$(OPENSSL_ROOT)/engines/qat_engine/ -lqae_mem_utils
endif
ifeq ($(CRYPTO_MEMORY_DRIVER),qae_mem)
QATSHAREDLIBDEPS += -Wl,-rpath,$(CMN_ROOT) -L$(CMN_ROOT) -lqae_mem_s
QATSHAREDLIBDEPS += -L$(OPENSSL_ROOT)/engines/qat_engine/ -lqat_mem_drv_inf
endif
QATLIBNAME=qat

.PHONEY: all lib 

top: 
	(cd $(TOP); $(MAKE) DIRS=engines EDIRS=$(DIR) sub_all)

all: errors lib

tags:
	ctags $(SRC)

errors:
	perl ../../util/mkerr.pl -conf e_qat.ec -nostatic -write $(SRC)

lib: $(QATLIBOBJ) $(QATLIBMEMOBJ)
	@if [ -n "$(SHARED_LIBS)" ]; then \
		$(MAKE) -f $(TOP)/Makefile.shared -e \
			LIBNAME=$(QATLIBMEM) \
			LIBEXTRAS='$(QATLIBMEMOBJ)' \
			LIBDEPS='$(QATLIBMEMDEPS)' \
			link_o.$(SHLIB_TARGET); \
		$(MAKE) -f $(TOP)/Makefile.shared -e \
                        LIBNAME=$(QATLIBNAME) \
                        LIBEXTRAS='$(QATLIBOBJ_SHARED)' \
                        LIBDEPS='$(QATSHAREDLIBDEPS)' \
                        link_o.$(SHLIB_TARGET); \
	else \
		$(AR) $(QATLIBTARGET) $(QATLIBOBJ); \
	fi


install:
	[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		echo installing $(QATLIBNAME); \
		pfx=lib; \
		if [ "$(PLATFORM)" != "Cygwin" ]; then \
			case "$(CFLAGS)" in \
			*DSO_BEOS*) sfx=".so";; \
			*DSO_DLFCN*) sfx=".so";; \
			*DSO_DL*) sfx=".sl";; \
			*DSO_WIN32*) sfx="eay32.dll"; pfx=;; \
			*) sfx=".bad";; \
			esac; \
			cp $${pfx}$(QATLIBNAME)$$sfx $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(QATLIBNAME)$$sfx.new; \
			cp $${pfx}$(QATLIBMEM)$$sfx $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/$${pfx}$(QATLIBMEM)$$sfx.new; \
		else \
			sfx=".so"; \
			cp cyg$(QATLIBNAME).dll $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(QATLIBNAME)$$sfx.new; \
			cp cyg$(QATLIBMEM).dll $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/$${pfx}$(QATLIBMEM)$$sfx.new; \
		fi; \
		chmod 555 $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(QATLIBNAME)$$sfx.new; \
		mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(QATLIBNAME)$$sfx.new $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(QATLIBNAME)$$sfx; \
		chmod 555 $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/$${pfx}$(QATLIBMEM)$$sfx.new; \
                mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/$${pfx}$(QATLIBMEM)$$sfx.new $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/$${pfx}$(QATLIBMEM)$$sfx; \
	fi

qae_mem_utils.o: qae_mem_utils.c
	$(CC) $(CFLAGS) -c -o qae_mem_utils.o qae_mem_utils.c

qat_mem_drv_inf.o: qat_mem_drv_inf.c
	$(CC) $(CFLAGS) -c -o qat_mem_drv_inf.o qat_mem_drv_inf.c

links:

tests:

depend: errors
	@if [ -z "$(THIS)" ]; then \
	    $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; \
	else \
	    $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(QATLIBSRC); \
	fi

files:



lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff *.so *.sl *.dll e_qat_err.*

# DO NOT DELETE THIS LINE -- make depend depends on it.

e_qat.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
e_qat.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
e_qat.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
e_qat.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
e_qat.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
e_qat.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
e_qat.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
e_qat.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
e_qat.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
e_qat.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
e_qat.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
e_qat.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
e_qat.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
e_qat.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h e_qat.c
e_qat.o: e_qat.h e_qat_err.h qae_mem_utils.h qat_ciphers.h qat_dh.h
e_qat.o: qat_digests.h qat_dsa.h qat_ecdh.h qat_ecdsa.h qat_parseconf.h
e_qat.o: qat_rand.h qat_rsa.h qat_sym_common.h qat_utils.h
e_qat_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
e_qat_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
e_qat_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
e_qat_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
e_qat_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
e_qat_err.o: ../../include/openssl/symhacks.h e_qat_err.c e_qat_err.h
qae_mem_utils.o: qae_mem_utils.c qae_mem_utils.h
qat_asym_common.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
qat_asym_common.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
qat_asym_common.o: ../../include/openssl/buffer.h
qat_asym_common.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
qat_asym_common.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
qat_asym_common.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
qat_asym_common.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
qat_asym_common.o: ../../include/openssl/obj_mac.h
qat_asym_common.o: ../../include/openssl/objects.h
qat_asym_common.o: ../../include/openssl/opensslconf.h
qat_asym_common.o: ../../include/openssl/opensslv.h
qat_asym_common.o: ../../include/openssl/ossl_typ.h
qat_asym_common.o: ../../include/openssl/pkcs7.h
qat_asym_common.o: ../../include/openssl/safestack.h
qat_asym_common.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
qat_asym_common.o: ../../include/openssl/symhacks.h
qat_asym_common.o: ../../include/openssl/x509.h
qat_asym_common.o: ../../include/openssl/x509_vfy.h e_qat.h qae_mem_utils.h
qat_asym_common.o: qat_asym_common.c qat_asym_common.h qat_ciphers.h
qat_asym_common.o: qat_digests.h qat_sym_common.h qat_utils.h
qat_chain.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
qat_chain.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
qat_chain.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
qat_chain.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
qat_chain.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
qat_chain.o: ../../include/openssl/err.h ../../include/openssl/evp.h
qat_chain.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
qat_chain.o: ../../include/openssl/objects.h
qat_chain.o: ../../include/openssl/opensslconf.h
qat_chain.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
qat_chain.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
qat_chain.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
qat_chain.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
qat_chain.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
qat_chain.o: e_qat.h e_qat_err.h qae_mem_utils.h qat_chain.c qat_chain.h
qat_chain.o: qat_ciphers.h qat_digests.h qat_sym_common.h qat_utils.h
qat_ciphers.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
qat_ciphers.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
qat_ciphers.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
qat_ciphers.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
qat_ciphers.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
qat_ciphers.o: ../../include/openssl/err.h ../../include/openssl/evp.h
qat_ciphers.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
qat_ciphers.o: ../../include/openssl/objects.h
qat_ciphers.o: ../../include/openssl/opensslconf.h
qat_ciphers.o: ../../include/openssl/opensslv.h
qat_ciphers.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
qat_ciphers.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
qat_ciphers.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
qat_ciphers.o: ../../include/openssl/tls1.h ../../include/openssl/x509.h
qat_ciphers.o: ../../include/openssl/x509_vfy.h e_qat.h e_qat_err.h
qat_ciphers.o: qae_mem_utils.h qat_chain.h qat_ciphers.c qat_ciphers.h
qat_ciphers.o: qat_digests.h qat_sym_common.h qat_utils.h
qat_dh.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
qat_dh.o: ../../include/openssl/dh.h ../../include/openssl/e_os2.h
qat_dh.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
qat_dh.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
qat_dh.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
qat_dh.o: qae_mem_utils.h qat_asym_common.h qat_dh.c qat_dh.h qat_utils.h
qat_digests.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
qat_digests.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
qat_digests.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
qat_digests.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
qat_digests.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
qat_digests.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
qat_digests.o: ../../include/openssl/md5.h ../../include/openssl/obj_mac.h
qat_digests.o: ../../include/openssl/objects.h
qat_digests.o: ../../include/openssl/opensslconf.h
qat_digests.o: ../../include/openssl/opensslv.h
qat_digests.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
qat_digests.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
qat_digests.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
qat_digests.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
qat_digests.o: e_qat.h e_qat_err.h qae_mem_utils.h qat_ciphers.h qat_digests.c
qat_digests.o: qat_digests.h qat_sym_common.h qat_utils.h
qat_dsa.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
qat_dsa.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
qat_dsa.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
qat_dsa.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
qat_dsa.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
qat_dsa.o: qat_asym_common.h qat_dsa.c qat_dsa.h qat_utils.h
qat_ecdh.o: ../../crypto/ecdh/ech_locl.h ../../include/openssl/aes.h
qat_ecdh.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
qat_ecdh.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
qat_ecdh.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
qat_ecdh.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
qat_ecdh.o: ../../include/openssl/engine.h ../../include/openssl/err.h
qat_ecdh.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
qat_ecdh.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
qat_ecdh.o: ../../include/openssl/opensslconf.h
qat_ecdh.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
qat_ecdh.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
qat_ecdh.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
qat_ecdh.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
qat_ecdh.o: ../../include/openssl/x509_vfy.h e_qat.h e_qat_err.h
qat_ecdh.o: qae_mem_utils.h qat_asym_common.h qat_ciphers.h qat_digests.h
qat_ecdh.o: qat_ecdh.c qat_ecdh.h qat_sym_common.h qat_utils.h
qat_ecdsa.o: ../../crypto/ecdsa/ecs_locl.h ../../include/openssl/aes.h
qat_ecdsa.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
qat_ecdsa.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
qat_ecdsa.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
qat_ecdsa.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
qat_ecdsa.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
qat_ecdsa.o: ../../include/openssl/err.h ../../include/openssl/evp.h
qat_ecdsa.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
qat_ecdsa.o: ../../include/openssl/objects.h
qat_ecdsa.o: ../../include/openssl/opensslconf.h
qat_ecdsa.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
qat_ecdsa.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
qat_ecdsa.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
qat_ecdsa.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
qat_ecdsa.o: ../../include/openssl/x509_vfy.h e_qat.h e_qat_err.h
qat_ecdsa.o: qae_mem_utils.h qat_asym_common.h qat_ciphers.h qat_digests.h
qat_ecdsa.o: qat_ecdsa.c qat_ecdsa.h qat_sym_common.h qat_utils.h
qat_parseconf.o: qat_parseconf.c qat_parseconf.h qat_utils.h
qat_rand.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
qat_rand.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
qat_rand.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
qat_rand.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
qat_rand.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
qat_rand.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
qat_rand.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
qat_rand.o: ../../include/openssl/opensslconf.h
qat_rand.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
qat_rand.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
qat_rand.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
qat_rand.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
qat_rand.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
qat_rand.o: e_qat.h qae_mem_utils.h qat_ciphers.h qat_digests.h qat_rand.c
qat_rand.o: qat_rand.h qat_sym_common.h qat_utils.h
qat_rsa.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
qat_rsa.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
qat_rsa.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
qat_rsa.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
qat_rsa.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
qat_rsa.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
qat_rsa.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
qat_rsa.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
qat_rsa.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
qat_rsa.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
qat_rsa.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
qat_rsa.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
qat_rsa.o: ../../include/openssl/x509_vfy.h e_qat.h e_qat_err.h qae_mem_utils.h
qat_rsa.o: qat_asym_common.h qat_ciphers.h qat_digests.h qat_rsa.c qat_rsa.h
qat_rsa.o: qat_sym_common.h qat_utils.h
qat_sym_common.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
qat_sym_common.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
qat_sym_common.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
qat_sym_common.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
qat_sym_common.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
qat_sym_common.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
qat_sym_common.o: ../../include/openssl/obj_mac.h
qat_sym_common.o: ../../include/openssl/objects.h
qat_sym_common.o: ../../include/openssl/opensslconf.h
qat_sym_common.o: ../../include/openssl/opensslv.h
qat_sym_common.o: ../../include/openssl/ossl_typ.h
qat_sym_common.o: ../../include/openssl/pkcs7.h
qat_sym_common.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
qat_sym_common.o: ../../include/openssl/stack.h
qat_sym_common.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
qat_sym_common.o: ../../include/openssl/x509_vfy.h e_qat.h qae_mem_utils.h
qat_sym_common.o: qat_ciphers.h qat_digests.h qat_sym_common.c qat_sym_common.h
qat_sym_common.o: qat_utils.h
qat_utils.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
qat_utils.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
qat_utils.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
qat_utils.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
qat_utils.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
qat_utils.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
qat_utils.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
qat_utils.o: ../../include/openssl/opensslconf.h
qat_utils.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
qat_utils.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
qat_utils.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
qat_utils.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
qat_utils.o: ../../include/openssl/x509_vfy.h e_qat.h qat_ciphers.h
qat_utils.o: qat_digests.h qat_sym_common.h qat_utils.c qat_utils.h
