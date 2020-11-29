CLANG := clang
BPF_EXTRA_FLAGS := -fno-stack-protector -g
LLC := llc
LLC_EXTRA_FLAGS := -mattr=dwarfris

ARCH := __x86_64__

hello1_kern.o: hello1_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@

LDFLAGS := $(shell pkg-config --libs libbpf)	\
			$(shell pkg-config --libs libelf)	\
			$(shell pkg-config --libs zlib)

hello: hello_user.o ../lib/bpf_load.o
	$(CC) -o $@ $< $(LDFLAGS) ../lib/bpf_load.o

hello2_kern.o: hello2_kern.c
	$(CLANG) $(BPF_EXTRA_FLAGS) -D$(ARCH) -O2 -emit-llvm -c $< -o - | \
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@
