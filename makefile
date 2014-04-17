.PHONY: all clean depend ksview
.SECONDARY:

# -- Variables ----
CC ?= gcc

LDFLAGS ?= -g -ggdb -Werror -pedantic -Wl,--hash-style=gnu,-O1 -Wl,--as-needed
LDFLAGS := $(LDFLAGS)
LDFLAGS += -Wall -Wextra

CFLAGS ?= -O2 -g -ggdb -Werror -pedantic
CFLAGS += -Wall -Wextra -Wbad-function-cast -Wcast-align -Wcast-qual \
	-Wfloat-equal -Wformat=1 \
	-Winline -Wlogical-op -Wnested-externs -Wno-missing-field-initializers \
	-Wno-unused-parameter -Wold-style-definition -Wpointer-arith \
	-Wredundant-decls -Wshadow -Wstrict-aliasing=2 -Wstrict-overflow=5 \
	-Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wundef \
	-Wno-missing-braces -Wunreachable-code
CFLAGS += -std=gnu99 -I.

all: ksview

B := build/

clean:
	rm -rf -- $(B)

%/:
	mkdir -p $@

# -----------------------------------------------------------------------------


PACKAGES := openssl
ksview: LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs ${PACKAGES})
ksview: CFLAGS := $(shell pkg-config --cflags ${PACKAGES}) $(CFLAGS)

SOURCES := $(wildcard ksview/*.c) $(wildcard helpers/*.c)
OBJECTS := $(patsubst %.c, build/%.o, ${SOURCES})

depend:
	$(CC) $(CFLAGS) -MM $(SOURCES) > depend.mk
	sed -i "s=^=$(B)ksview/=" depend.mk
	cat depend.mk

-include depend.mk

$(B)ksview/%.o: ksview/%.c | $(B)ksview/
	$(CC) $^ $(CFLAGS) -c -o $@

$(B)bin/ksview: $(OBJECTS) | $(B)bin/
	$(CC) $^ $(LDFLAGS) -o $@

ksview: $(B)bin/ksview
