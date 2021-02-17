CLANG := clang
LLC := llc
OPT := opt
LLVM_DIS := llvm-dis
LLVM_OBJCOPY := llvm-objcopy
BTF_PAHOLE := pahole

NOSTDINC_FLAGS = -nostdinc -isystem $(shell $(CC) -print-file-name=include) -I/usr/include

BTF_LLC_PROBE := $(shell $(LLC) -march=bpf -mattr=help 2>&1 | grep dwarfris)
BTF_PAHOLE_PROBE := $(shell $(BTF_PAHOLE) --help 2>&1 | grep BTF)
BTF_OBJCOPY_PROBE := $(shell $(LLVM_OBJCOPY) --help 2>&1 | grep -i 'usage.*llvm')
BTF_LLVM_PROBE := $(shell echo "int main() { return 0; }" | \
					$(CLANG) -target bpf -O2 -g -c -x c - -o ./llvm_btf_verify.o; \
					readelf -S ./llvm_btf_verify.o | grep BTF; \
					/bin/rm -f ./llvm_btf_verify.o)

BPF_EXTRA_CFLAGS :=
LLC_EXTRA_FLAGS :=
ifneq ($(BTF_LLVM_PROBE),)
	# if llvm support btf, just add `-g`
	BPF_EXTRA_CFLAGS += -g
else
	# otherwise generate info from dwarfris
ifneq ($(and $(BTF_LLC_PROBE),$(BTF_PAHOLE_PROBE),$(BTF_OBJCOPY_PROBE)),)
	BPF_EXTRA_CFLAGS += -g
	LLC_EXTRA_FLAGS += -mattr=dwarfris
	DWARF2BTF = y
endif
endif

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

connect_kern.o: connect_kern.c
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(CLANG) -target bpf	\
		$(NOSTDINC_FLAGS) $(BPF_EXTRA_CFLAGS)	\
		-D$(ARCH) -O2 -emit-llvm -Xclang -disable-llvm-passes -c $< -o - |	\
		$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) |	\
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@
ifeq ($(DWARF2BTF),y)
	 $(BTF_PAHOLE) -J $@
endif

connect: connect_kern.o connect.c connect_kern.c
	bpftool gen skeleton $@_kern.o > $@_kern.skel.h
	$(CLANG) -o $@ $@.c $(LDFLAGS)

all: connect_kern.o connect

clean:
	rm -rf *.o connect *.skel.h vmlinux.h

.PYONY: all clean
