#************************************************
# Makefile.am for UXDS POSIX Account tool suite *
#************************************************
OBJECTS = `find ./* -name '*.o'`

if SUDOON
bin_PROGRAMS = lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
bin_PROGRAMS = lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

lacctparse_SOURCES = 
	config.h \
	uxds.h \
	uxds_sasl.h \
	uxds_krb5.h \
	uxds_log.h \
	uxds_strings.h \
	strings.c \
	args.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	lacctparse.c 

luseradd_SOURCES = 
	config.h \
	uxds.h \
        uxds_sasl.h \
        uxds_krb5.h \
	uxds_log.h \
	uxds_strings.h \
	strings.c \
	args.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	luseradd.c

lgroupadd_SOURCES =
	config.h \
	uxds.h \
        uxds_sasl.h \
        uxds_krb5.h \
	uxds_log.h \
        uxds_strings.h \
	args.c \
	strings.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
        sasl.c \
	krb5.c \
	lgroupadd.c

luserdel_SOURCES =
	config.h \
	uxds.h \
	uxds_sasl.h \
        uxds_krb5.h \
        uxds_log.h \
        uxds_strings.h \
	args.c \
	strings.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	lgroupdel.c

lgroupdel_SOURCES =
	config.h \
	uxds.h \
        uxds_sasl.h \
        uxds_krb5.h \
        uxds_log.h \
        uxds_strings.h \
	args.c \
	strings.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	lgroupdel.c

lusermod_SOURCES =
	config.h \
	uxds.h \
        uxds_sasl.h \
        uxds_krb5.h \
        uxds_log.h \
        uxds_strings.h \
	args.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	strings.c \
	lusermod.c

lgroupmod_SOURCES =
	config.h \
	uxds.h \
        uxds_sasl.h \
        uxds_krb5.h \
        uxds_log.h \
        uxds_strings.h \
	args.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	strings.c \
	lgroupmod.c

lsudoadd_SOURCES =
	config.h \
	uxds.h \
        uxds_sasl.h \
        uxds_krb5.h \
        uxds_log.h \
        uxds_strings.h \
	args.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	sudoldap.c \
	strings.c \
	lsudoadd.c

lsudodel_SOURCES =
	config.h \
	uxds.h \
        uxds_sasl.h \
        uxds_krb5.h \
        uxds_log.h \
        uxds_strings.h \
	args.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	sudoldap.c \
	strings.c \
	lsudodel.c

lsudomod_SOURCES =
	config.h \
	uxds.h \
        uxds_sasl.h \
        uxds_krb5.h \
        uxds_log.h \
        uxds_strings.h \
	args.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	sudoldap.c \
	strings.c \
	lsudomod.c

SRCS = uxds.h uxds_sasl.h uxds_krb5.h uxds_log.h uxds_strings.h strings.c sasl.c krb5.c ldap.c sudoldap.c 

LDFLAGS = -lldap

if GSSAPI 
OBJS = -lkrb5 args.o strings.o krb5.o sasl.o ldap.o
SUOBJS = -lkrb5 sudoldap.o args.o strings.o krb5.o sasl.o ldap.o
else
OBJS = args.o strings.o sasl.o ldap.o
SUOBJS = sudoldap.o args.o strings.o sasl.o ldap.o
endif

if PTS
AFSFLAG = -lkafs
endif

if LOGGER
LOGOBJS = log.o
endif

CFLAGS = -I/usr/local/include -Wall -g -c
DEBUG = -O2

if SUDOON
all: lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
all: lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

all-debug: lacctparse_debug luseradd_debug

lacctparse_debug: ${OBJS} ${LOGOBJS} lacctparse.o
	${CC} ${DEBUG} ${LDFLAGS} ${AFSFLAG} ${OBJS} ${LOGOBJS} lacctparse.o -o lacctparse

lacctparse: ${OBJS} ${LOGOBJS} lacctparse.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${OBJS} ${LOGOBJS} lacctparse.o -o lacctparse

luseradd: ${OBJS} ${LOGOBJS} luseradd.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${OBJS} ${LOGOBJS} luseradd.o -o luseradd

lgroupadd: ${OBJS} ${LOGOBJS} lgroupadd.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${OBJS} ${LOGOBJS} lgroupadd.o -o lgroupadd

luserdel: ${OBJS} ${LOGOBJS} luserdel.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${OBJS} ${LOGOBJS} luserdel.o -o luserdel

lgroupdel: ${OBJS} ${LOGOBJS} lgroupdel.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${OBJS} ${LOGOBJS} lgroupdel.o -o lgroupdel

lusermod: ${OBJS} ${LOGOBJS} lusermod.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${OBJS} ${LOGOBJS} lusermod.o -o lusermod

lgroupmod: ${OBJS} ${LOGOBJS} lgroupmod.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${OBJS} ${LOGOBJS} lgroupmod.o -o lgroupmod

if SUDOON
sudoldap.o: uxds.h  sudoldap.c
	${CC} ${DEBUG} ${CFLAGS} sudoldap.c

lsudoadd.o: uxds.h  lsudoadd.c
	${CC} ${DEBUG} ${CFLAGS} lsudoadd.c

lsudodel.o:: uxds.h  lsudodel.c
	${CC} ${DEBUG} ${CFLAGS} lsudodel.c

lsudomod.o: uxds.h  lsudomod.c
	${CC} ${DEBUG} ${CFLAGS} lsudomod.c

lsudoadd: ${SUOBJS} ${LOGOBJS} lsudoadd.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${SUOBJS} ${LOGOBJS} lsudoadd.o -o lsudoadd

lsudodel: ${SUOBJS} ${LOGOBJS} lsudodel.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${SUOBJS} ${LOGOBJS} lsudodel.o -o lsudodel

lsudomod: ${SUOBJS} ${LOGOBJS} lsudomod.o
	${CC} ${LDFLAGS} ${AFSFLAG} ${SUOBJS} ${LOGOBJS} lsudomod.o -o lsudomod
endif

luseradd_debug: ${OBJS} ${LOGOBJS} luseradd.o
	${CC} ${DEBUG} ${LDFLAGS} ${AFSFLAG} ${OBJS} ${LOGOBJS} luseradd.o -o luseradd

strings.o: uxds.h uxds_strings.h strings.c
	${CC} ${DEBUG} ${CFLAGS} strings.c

log.o: uxds.h uxds_log.h log.c
	${CC} ${DEBUG} ${CFLAGS} log.c

base64.o: uxds.h uxds_strings.h base64.c
	${CC} ${DEBUG} ${CFLAGS} base64.c

sasl.o: uxds.h uxds_sasl.h sasl.c
	${CC} ${DEBUG} ${CFLAGS} sasl.c

krb5.o: uxds.h uxds_krb5.h krb5.c 
	${CC} ${DEBUG} ${CFLAGS} krb5.c

ldap.o: uxds.h uxds_strings.h ldap.c
	${CC} ${DEBUG} ${CFLAGS} ldap.c

args.o: uxds.h uxds_strings.h args.c
	${CC} ${DEBUG} ${CFLAGS} args.c

lacctparse.o: uxds.h lacctparse.c
	${CC} ${DEBUG} ${CFLAGS} lacctparse.c

luseradd.o: uxds.h luseradd.c
	${CC} ${DEBUG} ${CFLAGS} luseradd.c

lgroupadd.o: uxds.h lgroupadd.c
	${CC} ${DEBUG} ${CFLAGS} lgroupadd.c

luserdel.o: uxds.h luserdel.c
	${CC} ${DEBUG} ${CFLAGS} luserdel.c

lgroupdel.o: uxds.h lgroupdel.c
	${CC} ${DEBUG} ${CFLAGS} lgroupdel.c

lusermod.o: uxds.h lusermod.c
	${CC} ${DEBUG} ${CFLAGS} lusermod.c

lgroupmod.o: uxds.h lgroupmod.c
	${CC} ${DEBUG} ${CFLAGS} lgroupmod.c

clean:
if SUDOON
	rm -rf *.o
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod" || rm -f lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
	rm -rf *.o
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod" || rm -f lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

strip:
if SUDOON
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod" || strip -s lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod" || strip -s lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

install: strip install-am
