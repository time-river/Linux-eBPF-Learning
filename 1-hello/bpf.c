#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size) {
	return syscall(__NR_bpf, cmd, attr, size);
}

static inline int sys_bpf_prog_load(union bpf_attr *attr, unsigned int size) {
	int fd;

	do {
		fd = sys_bpf(BPF_PROG_LOAD, attr, size);
	} while (fd < 0 && errno == EAGAIN);

	return fd;
}

int bpf_load_program(enum bpf_prog_type type,
		     const struct bpf_insn *insns, size_t insns_cnt,
		     const char *license, const char *prog_name,
		     char *log_buf, size_t log_buf_sz) {
	union bpf_attr attr = {0};

	attr.prog_type = BPF_PROG_TYPE_KPROBE;

	attr.insns = (unsigned long)insns;
	attr.insn_cnt = (unsigned int)insns_cnt;

	memcpy(attr.prog_name, prog_name,
	       strlen(prog_name) < BPF_OBJ_NAME_LEN ? \
		strlen(prog_name) : BPF_OBJ_NAME_LEN);

	attr.log_level = 8; // BPF_LOG_KERNEL
	attr.log_buf = (unsigned long)log_buf;
	attr.log_size = log_buf_sz;


	return sys_bpf_prog_load(&attr, sizeof(attr));
}
