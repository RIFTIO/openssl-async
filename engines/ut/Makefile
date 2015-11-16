DEBUG=1

OPENSSL_DIR=/opt/ws/git_workspace/fibre
OPENSSL_ENG=${OPENSSL_DIR}/engines
OPENSSL_UT=${OPENSSL_ENG}/ut
OPENSSL_INS=${OPENSSL_DIR}/install
OPENSSL_INC=${OPENSSL_INS}/include


ifdef DEBUG
FLAGS = -ggdb3
else
FLAGS = -O3
endif

INC_DIRS_INTERNAL = \
	-I${OPENSSL_DIR} \
	-I${OPENSSL_ENG} \
	-I${OPENSSL_DIR}/include/internal \
	-I${OPENSSL_DIR}/crypto \
	-I${OPENSSL_DIR}/crypto/include 

S_FILES= \
	${OPENSSL_ENG}/e_afalg.c 

M_FILES= \
	${OPENSSL_UT}/error_mock.c \
	${OPENSSL_UT}/engine_mock.c \

T_FILES=${OPENSSL_UT}/test_e_afalg.c

FLAGS +=-D_GNU_SOURCE_ -DAFALG_NO_UNIT_TEST -I${OPENSSL_INC} ${INC_DIRS_INTERNAL}

ifdef RUN_UTEST
all: exe run
else
all: exe
endif

run: exe
	./utest

exe:
	gcc -o utest ${FLAGS} ${T_FILES} ${S_FILES} ${M_FILES}

