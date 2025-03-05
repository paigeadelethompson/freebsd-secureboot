# $FreeBSD$

.PATH: ${.CURDIR}/../../common

PROG=	pkinstall.efi
MAN=	pkinstall.8
SRCS=	pkinstall.c

# EFI build configuration
EFI_TARGET=	efi-app-x86_64
EFI_CRT0=	${EFI_CRT}
EFI_LDSTART=	${EFI_LDSTART}
EFI_LDSCRIPT=	${EFI_LDSCRIPT}

# Include paths
CFLAGS+=	-I${.CURDIR}/../../common
CFLAGS+=	-I${.CURDIR}/../../../sys/boot/efi/include
CFLAGS+=	-I${.CURDIR}/../../../sys/boot/efi/include/${MACHINE}

# EFI specific flags
CFLAGS+=	-fPIC
CFLAGS+=	-fshort-wchar
CFLAGS+=	-mno-red-zone
CFLAGS+=	-fno-stack-protector
CFLAGS+=	-fno-stack-check
CFLAGS+=	-fno-strict-aliasing
CFLAGS+=	-Wno-pointer-sign
CFLAGS+=	-Wno-unused-parameter

# Link flags
LDFLAGS+=	-T ${EFI_LDSCRIPT}
LDFLAGS+=	-shared
LDFLAGS+=	-Bsymbolic
LDFLAGS+=	-znocombreloc

# Libraries
LDADD+=		${EFI_CRT0}
LDADD+=		${EFI_LDSTART}

.include <bsd.prog.mk> 