CLANG := clang
LLC := llc

LIBBPF := $(shell pkg-config --exists libbpf; echo $$?)
LIBELF := $(shell pkg-config --exists libelf; echo $$?)

ifneq ($(LIBBPF),0)
  $(error "no libbpf, install libbpf-dev or libbpf-devel")
endif

ifneq ($(LIBELF),0)
  $(error "no libelf, install libelf-dev or libelf-devel")
endif

.PYONY: all clean

all: hello hello_kern.o

clean:
	rm -rf *.o hello

LDFLAGS := $(shell pkg-config --libs libbpf)	\
			$(shell pkg-config --libs libelf)

hello_kern.o: hello_kern.c
	$(CLANG) -O2 -emit-llvm -c $< -o - | \
		$(LLC) -march=bpf -filetype=obj -o $@

hello: hello_user.o bpf_load.o
	$(CC) -o $@ $< $(LDFLAGS) bpf_load.o
