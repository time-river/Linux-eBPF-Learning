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

all: hello openat1_kern.o openat2_kern.o openat3_kern.o openat4_kern.o

clean:
	rm -rf *.o hello

.PYONY: all clean

hello_kern.o: hello_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

hello: hello_user.o bpf_load.o
	$(CC) -o $@ $< $(LDFLAGS) bpf_load.o

openat1_kern.o: openat1_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

openat2_kern.o: openat2_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

openat3_kern.o: openat3_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -g -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

openat4_kern.o: openat4_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@
