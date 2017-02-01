#************************************************
# Makefile.am for UXDS POSIX Account tool suite *
#************************************************
OBJECTS = `find ./* -name '*.o'`

if SUDOON
bin_PROGRAMS = libuxds lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
bin_PROGRAMS = libuxds lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

libuxds_SOURCES =
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
	sudoldap.c \
	sasl.c \
	krb5.c

lacctparse_SOURCES = 
	uxds.h \
	lacctparse.c 

luseradd_SOURCES = 
	uxds.h \
	luseradd.c

lgroupadd_SOURCES =
	uxds.h \
	lgroupadd.c

luserdel_SOURCES =
	uxds.h \
	lgroupdel.c

lgroupdel_SOURCES =
	uxds.h \
	lgroupdel.c

lusermod_SOURCES =
	uxds.h \
	lusermod.c

lgroupmod_SOURCES =
	uxds.h \
	lgroupmod.c

lsudoadd_SOURCES =
	uxds.h \
	lsudoadd.c

lsudodel_SOURCES =
	uxds.h \
	lsudodel.c

lsudomod_SOURCES =
	uxds.h \
	lsudomod.c

SRCS = uxds.h uxds_sasl.h uxds_krb5.h uxds_log.h uxds_strings.h strings.c sasl.c krb5.c ldap.c sudoldap.c 
CFLAGS = -I/usr/local/include -Wall -g -c
SOFLAGS = -shared -Wl,-soname,libuxds.so.0
LDFLAGS = -L/usr/local/lib -lldap -llber
BINFLAGS = -I/usr/local/include -Wall -g
DEBUG = -fPIC
UXDSLIB = libuxds.so.0.8.5

OBJS = args.o strings.o ldap.o
if SUDOON
SUOBJS = sudoldap.o
endif 

if SASL
SASLOBJS = sasl.o
endif

if GSSAPI 
GSS = -lkrb5 -lcrypto -lroken
K5OBJS = krb5.o
endif

if PTS
AFSFLAG = -lkafs
endif

if LOGGER
LOGOBJS = log.o
endif

if SUDOON
all: libuxds lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
all: libuxds lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

all-debug: lib lacctparse_debug luseradd_debug

libuxds$(EXEEXT): ${OBJS} ${SUOBJS} ${K5OBJS} ${LOGOBJS} ${SASLOBJS}
	${CC} ${SOFLAGS} ${OBJS} ${SUOBJS} ${K5OBJS} ${LOGOBJS} ${SASLOBJS} -o ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

lacctparse$(EXEEXT): lacctparse.o
	${CC} ${BINFLAGS} lacctparse.o -o lacctparse ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

luseradd$(EXEEXT): luseradd.o
	${CC} ${BINFLAGS} luseradd.o -o luseradd ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

lgroupadd$(EXEEXT): lgroupadd.o
	${CC} ${BINFLAGS} lgroupadd.o -o lgroupadd ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

luserdel$(EXEEXT): luserdel.o
	${CC} ${BINFLAGS} luserdel.o -o luserdel ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

lgroupdel$(EXEEXT): lgroupdel.o
	${CC} ${BINFLAGS} lgroupdel.o -o lgroupdel ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

lusermod$(EXEEXT): lusermod.o
	${CC} ${BINFLAGS} lusermod.o -o lusermod ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

lgroupmod$(EXEEXT): lgroupmod.o
	${CC} ${BINFLAGS} lgroupmod.o -o lgroupmod ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

if SUDOON
sudoldap.o: uxds.h  sudoldap.c
	${CC} ${DEBUG} ${CFLAGS} sudoldap.c

lsudoadd.o: uxds.h  lsudoadd.c
	${CC} ${DEBUG} ${CFLAGS} lsudoadd.c

lsudodel.o: uxds.h  lsudodel.c
	${CC} ${DEBUG} ${CFLAGS} lsudodel.c

lsudomod.o: uxds.h  lsudomod.c
	${CC} ${DEBUG} ${CFLAGS} lsudomod.c
endif

strings.o: uxds.h uxds_strings.h strings.c
	${CC} ${DEBUG} ${CFLAGS} strings.c

log.o: uxds.h uxds_log.h log.c
	${CC} ${DEBUG} ${CFLAGS} log.c

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

if SUDOON
lsudoadd$(EXEEXT): lsudoadd.o
	${CC} ${BINFLAGS} lsudoadd.o -o lsudoadd ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

lsudodel$(EXEEXT): lsudodel.o
	${CC} ${BINFLAGS} lsudodel.o -o lsudodel ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}

lsudomod$(EXEEXT): lsudomod.o
	${CC} ${BINFLAGS} lsudomod.o -o lsudomod ${UXDSLIB} ${LDFLAGS} ${AFSFLAG} ${GSS}
endif

putlib$(EXEEXT):
	strip -s ${UXDSLIB}
	install ${UXDSLIB} ${prefix}/lib
	ldconfig
	rm -rf ${prefix}/include/uxds
	mkdir ${prefix}/include/uxds
	install uxds*.h ${prefix}/include/uxds 

clean:
if SUDOON
	rm -rf *.o *.so.*
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod" || rm -f lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
	rm -rf *.o *.so.*
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod" || rm -f lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

strip:
if SUDOON
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod" || strip -s lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod lsudoadd lsudodel lsudomod
else
	test -z "lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod" || strip -s lacctparse luseradd lgroupadd luserdel lgroupdel lusermod lgroupmod
endif

install: strip putlib install-am
