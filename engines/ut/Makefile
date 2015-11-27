DEBUG=1

OPENSSL_DIR=/root/clucey/afalg_proto/isg_cid-openssl_async
OPENSSL_ENG=${OPENSSL_DIR}/engines
OPENSSL_UT=${OPENSSL_ENG}/ut
OPENSSL_INS=${OPENSSL_DIR}/install
OPENSSL_INC=${OPENSSL_DIR}/include


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
	${OPENSSL_UT}/async_mock.c \
	${OPENSSL_UT}/engine_mock.c \

T_FILES=${OPENSSL_UT}/test_e_afalg.c

O_FILE=${OPENSSL_UT}/utest


ifdef USE_AIO
FLAGS +=  -DALG_USE_AIO
S_FILES += ${OPENSSL_ENG}/e_afalg_aio.c
endif

FLAGS +=-DAFALG_NO_UNIT_TEST -I${OPENSSL_INC} ${INC_DIRS_INTERNAL}

ifdef RUN_UTEST
all: run
else
all: exe
endif

run: exe
	@echo "------- Running Unit Tests ------"
	@${O_FILE} 2>/dev/null 

exe:
	@gcc -o ${O_FILE} ${FLAGS} ${T_FILES} ${S_FILES} ${M_FILES}

