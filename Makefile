override CFLAGS+=-Wall -Werror -D_GNU_SOURCE -g
OBJS=reptyr.o reallocarray.o attach.o
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	OBJS += platform/linux/linux_ptrace.o platform/linux/linux.o
endif
ifeq ($(UNAME_S),FreeBSD)
	OBJS += platform/freebsd/freebsd_ptrace.o platform/freebsd/freebsd.o
	LDFLAGS += -lprocstat
endif
# Note that because of how Make works, this can be overriden from the
# command-line.
#
# e.g. install to /usr with `make PREFIX=/usr`
PREFIX=/usr/local

all: reptyr

reptyr: $(OBJS)

ifeq ($(DISABLE_TESTS),)
test: reptyr test/victim PHONY
	python test/basic.py
	python test/tty-steal.py
else
test: all
endif

VICTIM_CFLAGS ?= $(CFLAGS)
VICTIM_LDFLAGS ?= $(LDFLAGS)
test/victim: test/victim.o
test/victim: override CFLAGS := $(VICTIM_CFLAGS)
test/victim: override LDFLAGS := $(VICTIM_LDFLAGS)

attach.o: reptyr.h ptrace.h
reptyr.o: reptyr.h reallocarray.h
ptrace.o: ptrace.h platform/platform.h $(wildcard platform/*/arch/*.h)

clean:
	rm -f reptyr $(OBJS) test/victim.o test/victim

install: reptyr
	install -d -m 755 $(DESTDIR)$(PREFIX)/bin/
	install -m 755 reptyr $(DESTDIR)$(PREFIX)/bin/reptyr
	install -d -m 755 $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 644 reptyr.1 $(DESTDIR)$(PREFIX)/share/man/man1/reptyr.1
	install -d -m 755 $(DESTDIR)$(PREFIX)/share/man/fr/man1
	install -m 644 reptyr.fr.1 $(DESTDIR)$(PREFIX)/share/man/fr/man1/reptyr.1

.PHONY: PHONY
