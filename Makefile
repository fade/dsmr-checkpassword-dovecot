PROG     = checkpassword-dovecot
SRCS     = checkpassword-dovecot.c

DESTDIR ?=
PREFIX  ?= /var/qmail
SBINDIR ?= $(PREFIX)/bin

# Honour Debian's CFLAGS / CPPFLAGS / LDFLAGS injected by dpkg-buildflags.
CFLAGS  ?= -O2 -Wall -Wextra -Wformat -Wformat-security
CPPFLAGS ?= -D_FORTIFY_SOURCE=2
LDFLAGS  ?=

CC      ?= cc

all: $(PROG)

$(PROG): $(SRCS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

install: $(PROG)
	install -D -m 0755 $(PROG) \
	    $(DESTDIR)$(SBINDIR)/$(PROG)
	install -D -m 0644 conf/99-dsmr-smtp-auth.conf \
	    $(DESTDIR)/etc/dovecot/conf.d/99-dsmr-smtp-auth.conf
	install -D -m 0755 scripts/dsmr-smtpauth \
	    $(DESTDIR)/usr/sbin/dsmr-smtpauth

clean:
	rm -f $(PROG)

.PHONY: all install clean
