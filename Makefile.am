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
	ldap.h \
	sasl.h \
	krb5.h \
	log.h \
	strings.h \
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
        sasl.h \
        krb5.h \
	log.h \
	strings.h \
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
        sasl.h \
        krb5.h \
	log.h \
        strings.h \
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
	sasl.h \
        krb5.h \
        log.h \
        strings.h \
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
        sasl.h \
        krb5.h \
        log.h \
        strings.h \
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
        sasl.h \
        krb5.h \
        log.h \
        strings.h \
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
        sasl.h \
        krb5.h \
        log.h \
        strings.h \
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
        sasl.h \
        krb5.h \
        log.h \
        strings.h \
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
        sasl.h \
        krb5.h \
        log.h \
        strings.h \
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
        sasl.h \
        krb5.h \
        log.h \
        strings.h \
	args.c \
	log.c \
	ldap.c \
        sasl.c \
        krb5.c \
	sudoldap.c \
	strings.c \
	lsudomod.c

man_MANS = lacctparse.1 luseradd.1 lusermod.1 luserdel.1 lgroupadd.1 lgroupmod.1 lgroupdel.1 lsudoadd.1 lsudomod.1 lsudodel.1

SRCS = uxds.h sasl.h krb5.h log.h strings.h strings.c sasl.c krb5.c ldap.c sudoldap.c 

if SASL
OBJS = -lkrb5 args.o strings.o sasl.o krb5.o ldap.o log.o
SUOBJS = -lkrb5 sudoldap.o args.o strings.o sasl.o krb5.o ldap.o log.o
else
OBJS = args.o strings.o ldap.o log.o
SUOBJS = sudoldap.o args.o strings.o ldap.o log.o
endif

LDFLAGS = -L/usr/local/lib -lldap 
CFLAGS = -I/usr/local/include -Wall -g -c
DEBUG = -O2 

if SUDOON
all: lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
all: lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

all-debug: lacctparse_debug luseradd_debug 

lacctparse_debug: ${OBJS} lacctparse.o
	${CC} ${DEBUG} ${LDFLAGS} ${OBJS} lacctparse.o -o lacctparse

lacctparse: ${OBJS} lacctparse.o
if GSSAPI
	${CC} ${LDFLAGS} -lssl ${OBJS} lacctparse.o -o lacctparse
else
	${CC} ${LDFLAGS} ${OBJS} lacctparse.o -o lacctparse
endif

luseradd: ${OBJS} luseradd.o
	${CC} ${LDFLAGS} ${OBJS} luseradd.o -o luseradd

lgroupadd: ${OBJS} lgroupadd.o
	${CC} ${LDFLAGS} ${OBJS} lgroupadd.o -o lgroupadd

luserdel: ${OBJS} luserdel.o
	${CC} ${LDFLAGS} ${OBJS} luserdel.o -o luserdel

lgroupdel: ${OBJS} lgroupdel.o
	${CC} ${LDFLAGS} ${OBJS} lgroupdel.o -o lgroupdel

lusermod: ${OBJS} lusermod.o
	${CC} ${LDFLAGS} ${OBJS} lusermod.o -o lusermod

lgroupmod: ${OBJS} lgroupmod.o
	${CC} ${LDFLAGS} ${OBJS} lgroupmod.o -o lgroupmod

if SUDOON
sudoldap.o: uxds.h  sudoldap.c
	${CC} ${DEBUG} ${CFLAGS} sudoldap.c

lsudoadd.o: uxds.h  lsudoadd.c
	${CC} ${DEBUG} ${CFLAGS} lsudoadd.c

lsudodel.o:: uxds.h  lsudodel.c
	${CC} ${DEBUG} ${CFLAGS} lsudodel.c

lsudomod.o: uxds.h  lsudomod.c
	${CC} ${DEBUG} ${CFLAGS} lsudomod.c

lsudoadd: ${SUOBJS} lsudoadd.o
	${CC} ${LDFLAGS} ${SUOBJS} lsudoadd.o -o lsudoadd

lsudodel: ${SUOBJS} lsudodel.o
	${CC} ${LDFLAGS} ${SUOBJS} lsudodel.o -o lsudodel

lsudomod: ${SUOBJS} lsudomod.o
	${CC} ${LDFLAGS} ${SUOBJS} lsudomod.o -o lsudomod
endif

luseradd_debug: ${OBJS} luseradd.o
	${CC} ${DEBUG} ${LDFLAGS} ${OBJS} luseradd.o -o luseradd

strings.o: uxds.h strings.h strings.c
	${CC} ${DEBUG} ${CFLAGS} strings.c

log.o: uxds.h log.h log.c
	${CC} ${DEBUG} ${CFLAGS} log.c

base64.o: uxds.h strings.h base64.c
	${CC} ${DEBUG} ${CFLAGS} base64.c

sasl.o: uxds.h sasl.h sasl.c
	${CC} ${DEBUG} ${CFLAGS} sasl.c

krb5.o: uxds.h krb5.h krb5.c 
	${CC} ${DEBUG} ${CFLAGS} krb5.c

ldap.o: uxds.h strings.h ldap.c
	${CC} ${DEBUG} ${CFLAGS} ldap.c

args.o: uxds.h strings.h args.c
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
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod" || strip -d lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod" || strip -d lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

install: install-am
