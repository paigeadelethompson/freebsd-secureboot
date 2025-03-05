# $FreeBSD$

PROG=	efi-sign
MAN=	efi-sign.8
SRCS=	efi-sign.c

# OpenSSL dependencies
CFLAGS+=	-I${OPENSSLINC}
LDFLAGS+=	-L${OPENSSLLIB}
LDADD+=		-lcrypto

.include <bsd.prog.mk> 