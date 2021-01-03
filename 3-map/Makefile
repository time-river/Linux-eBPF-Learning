CLANG := clang
NOSTDINC_FLAGS = -nostdinc -isystem $(shell $(CC) -print-file-name=include)
BPF_EXTRA_FLAGS := $(NOSTDINC_FLAGS) -I/usr/include
LLC := llc

LIBBPF := $(shell pkg-config --exists libbpf; echo $$?)
LIBELF := $(shell pkg-config --exists libelf; echo $$?)

ifneq ($(LIBBPF),0)
  $(error "no libbpf, install libbpf-dev or libbpf-devel")
endif

ifneq ($(LIBELF),0)
  $(error "no libelf, install libelf-dev or libelf-devel")
endif

LDFLAGS := $(shell pkg-config --libs libbpf)	\
			$(shell pkg-config --libs libelf)

ARCH := __$(shell uname -m)__

hello: hello_user.o bpf_load.o
	$(CC) -o $@ $< $(LDFLAGS) bpf_load.o

map1_kern.o: map1_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -g -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

map1: map1_user.o bpf_load.o
	$(CC) -o $@ $< $(LDFLAGS) bpf_load.o

map2_kern.o: map2_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -g -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@ -mattr=dwarfris

map2: map2_user.o bpf_load.o
	$(CC) -o $@ $< $(LDFLAGS) bpf_load.o

map3_kern.o: map3_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -g -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@ -mattr=dwarfris

map3: map3_kern.o
	bpftool gen skeleton map3_kern.o > $@_kern.skel.h
	$(CC) -o $@ map3.c -lbpf

all: hello map1_kern.o map1 map2_kern.o map2 map3

clean:
	rm -rf *.o hello map1 map2 map3 *.skel.h

.PYONY: all clean
