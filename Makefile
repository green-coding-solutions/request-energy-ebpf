CLANG       ?= clang
CC          ?= clang
PKG_CONFIG  ?= pkg-config

# Try pkg-config for libbpf flags; fall back to manual libs if unavailable.
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)
LDLIBS       := $(if $(LIBBPF_LDLIBS),$(LIBBPF_LDLIBS),-lbpf -lelf -lz)

BPF_CFLAGS ?= -O2 -g -target bpf
CFLAGS    ?= -O2 -g $(LIBBPF_CFLAGS)

BPF_OBJ   := http_energy.bpf.o
USER_BIN  := http_energy

.PHONY: all clean

all: $(BPF_OBJ) $(USER_BIN)

$(BPF_OBJ): http_energy.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): http_energy.c $(BPF_OBJ)
	$(CC) $(CFLAGS) http_energy.c -o $@ $(LDLIBS)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)
