CLANG			:=	clang
LLC				:= llc
OPT				:= opt
LLVM_DIS		:= llvm-dis
LLVM_OBJCOPY	:= llvm-objcopy
BTF_PAHOLE		:= pahole

NOSTDINC_FLAGS	:= -nostdinc -isystem $(shell $(CC) -print-file-name=include) -I/usr/include -I/usr/include/x86_64-linux-gnu
BTF_LLC_PROBE := $(shell $(LLC) -march=bpf -mattr=help 2>&1 | grep dwarfris)
BTF_PAHOLE_PROBE := $(shell $(BTF_PAHOLE) --help 2>&1 | grep BTF)
BTF_OBJCOPY_PROBE := $(shell $(LLVM_OBJCOPY) --help 2>&1 | grep -i 'usage.*llvm')
BTF_LLVM_PROBE := $(shell echo "int main() { return 0; }" | \
				  $(CLANG) -target bpf -O2 -g -c -x c - -o ./llvm_btf_verify.o; \
				  readelf -S ./llvm_btf_verify.o 2>/dev/null | grep BTF; \
				  /bin/rm -f ./llvm_btf_verify.o)

BPF_EXTRA_CFLAGS	:=
LLC_EXTRA_FLAGS		:=

ifneq ($(BTF_LLVM_PROBE),)
	BPF_EXTRA_CFLAGS += -g
else
ifneq ($(and $(BTF_LLC_PROBE),$(BTF_PAHOLE_PROBE),$(BTF_OBJCOPY_PROBE)),)
	BPF_EXTRA_CFLAGS += -g
	LLC_EXTRA_FLAGS += -mattr=dwarfris'DWARF2BTF = y
endif
endif

ARCH	:= __$(shell uname -m)__

ebpf_kern.o: ebpf_kern.c
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(CLANG) -target bpf	\
		$(NOSTDINC_FLAGS) $(BPF_EXTRA_CFLAGS)	\
		-D$(ARCH) -O2 -emit-llvm -Xclang -disable-llvm-passes -c $< -o - |	\
		$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) |	\
		$(LLC) $(LLC_EXTRA_FLAGS) -march=bpf -filetype=obj -o $@
ifeq ($(DWARF2BTF),y)
	$(BTF_PAHOLE) -J $@
endif
	bpftool gen skeleton $@ > ebpf_kern.skel.h

CFLAGS	+= -g

xdp: ebpf_kern.o param.o log.o acl.o main.o
	cc -o $@ param.o log.o acl.o main.o -lbpf -lresolv -lpthread -g

clean:
	rm -rf *.o xdp vmlinux.h ebpf_kern.skel.h
