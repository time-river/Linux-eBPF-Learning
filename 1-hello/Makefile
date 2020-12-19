CLANG := clang
NOSTDINC_FLAGS = -nostdinc -isystem $(shell $(CC) -print-file-name=include)
BPF_EXTRA_FLAGS := -fno-stack-protector $(NOSTDINC_FLAGS) -I/usr/include -g
LLC := llc
LLC_EXTRA_FLAGS := -mattr=dwarfris

ARCH := __x86_64__

hello1_kern.o: hello1_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

hello_kern_v2.1.o: hello_kern_v2.1.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -g -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

LDFLAGS := $(shell pkg-config --libs libbpf)	\
			$(shell pkg-config --libs libelf)	\
			$(shell pkg-config --libs zlib)

hello: hello_user.o ../lib/bpf_load.o
	$(CC) -o $@ $< $(LDFLAGS) ../lib/bpf_load.o

hello2_kern.o: hello2_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@


hello3_kern.o: hello3_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

hello4_kern.o: hello4_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@
