CFLAGS=-Wall -Werror -D_GNU_SOURCE -g
OBJS=reptyr.o ptrace.o attach.o

PREFIX=/usr/local

all: reptyr

reptyr: $(OBJS)

attach.o: reptyr.h ptrace.h
reptyr.o: reptyr.h
ptrace.o: ptrace.h $(wildcard arch/*.h)

clean:
	rm -f reptyr $(OBJS)

install: reptyr
	install -d -m 755 $(DESTDIR)$(PREFIX)/bin/
	install -m 755 reptyr $(DESTDIR)$(PREFIX)/bin/reptyr
