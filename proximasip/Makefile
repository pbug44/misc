PROG= proximasip
SRCS= util.c base64.c proximasip.c

CFLAGS= -g -Wall 
LDFLAGS= -g -Wall 
LDADD= -lcrypto -lssl

BINDIR=/usr/local/sbin

NOMAN=1

.ifdef DEFAULT_PASS
LDFLAGS += -DDEFAULT_PASS=\"${DEFAULT_PASS}\"
CFLAGS +=  -DDEFAULT_PASS=\"${DEFAULT_PASS}\"
.endif

.include <bsd.prog.mk>

