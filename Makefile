CC=	gcc
CFLAGS=	-Wall -Wextra -I/usr/local/include -I/usr/include
LDFLAGS=	-L/usr/local/lib -lcrypto -lssl

PROGRAMS=	sbin/tpmctl/tpmctl sbin/efi-sign/efi-sign

all: $(PROGRAMS)

sbin/tpmctl/tpmctl: sbin/tpmctl/tpmctl.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

sbin/efi-sign/efi-sign: sbin/efi-sign/efi-sign.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGRAMS) 