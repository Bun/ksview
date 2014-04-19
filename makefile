.PHONY: all clean depend
.SECONDARY:
.DELETE_ON_ERROR:


# -- Variables ----------------------------------------------------------------

CC ?= gcc
GCC_COLORS ?= error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01

LDFLAGS ?= -g -ggdb -Werror -pedantic -Wl,--hash-style=gnu,-O1 -Wl,--as-needed
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

B := build/

SOURCES := $(wildcard ksview/*.c)
OBJECTS := $(patsubst %.c, $(B)%.o, $(SOURCES))
PACKAGES := openssl


# -----------------------------------------------------------------------------

LDFLAGS += $(shell pkg-config --libs $(PACKAGES))
CFLAGS += $(shell pkg-config --cflags $(PACKAGES))

all: $(B)bin/ksview

clean:
	$(RM) -r $(B)

depend:
	$(CC) $(CFLAGS) -MM $(SOURCES) > depend.mk
	sed -i "s=^=$(B)ksview/=" depend.mk

-include depend.mk

%/:
	@echo " [DIR] $@"
	@mkdir -p $@

$(B)ksview/%.o: ksview/%.c | $(B)ksview/
	@echo " [CC]  $<"
	@$(CC) -c $< $(CFLAGS) -o $@

$(B)bin/ksview: $(OBJECTS) | $(B)bin/
	@echo " [BIN] $@"
	@$(CC) $^ $(LDFLAGS) -o $@
