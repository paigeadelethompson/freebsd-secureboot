# $FreeBSD$

PROG=	tpmctl
MAN=	tpmctl.8
SRCS=	tpmctl.c

# OpenSSL dependencies
CFLAGS+=	-I${OPENSSLINC}
LDFLAGS+=	-L${OPENSSLLIB}
LDADD+=		-lcrypto

.include <bsd.prog.mk> 