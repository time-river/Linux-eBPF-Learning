CLANG := clang
NOSTDINC_FLAGS = -nostdinc -isystem $(shell $(CC) -print-file-name=include)
BPF_EXTRA_FLAGS := $(NOSTDINC_FLAGS) -I/usr/include
LLC := llc

LDFLAGS := $(shell pkg-config --libs libbpf)	\
			$(shell pkg-config --libs libelf)	\
			$(shell pkg-config --libs zlib)

ARCH := __x86_64__

hello_kern.o: hello_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

hello: hello_user.o bpf_load.o
	$(CC) -o $@ $< $(LDFLAGS) bpf_load.o

openat1_kern.o: openat1_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -g -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

openat2_kern.o: openat2_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

openat3_kern.o: openat3_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

openat4_kern.o: openat4_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

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

all: hello hello_kern.o openat1_kern.o openat2_kern.o openat3_kern.o	\
	map1_kern.o map1 map2_kern.o map2

clean:
	rm -rf *.o hello map1 map2

.PYONY: all clean
