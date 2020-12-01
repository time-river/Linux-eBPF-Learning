/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/ptrace.h>

#ifdef __x86_64__
#  define SYSCALL(SYS) "__x64_" #SYS
#elif defined(__aarch64__)
#  define SYSCALL(SYS) "__arm64_" #SYS
#elif defined(__s390x__)
#  define SYSCALL(SYS) "__s390x_" #SYS
#else
#  define SYSCALL(SYS)  #SYS
#endif

SEC("kprobe/" SYSCALL(sys_openat))
int hello(struct pt_regs *ctx) {
	struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
	char fmt[] = "@dirfd='%d' @pathname='%s' @flags=0x%x";
	int dirfd = PT_REGS_PARM1_CORE(real_regs);
	char *pathname = (char *)PT_REGS_PARM2_CORE(real_regs);
	unsigned long flags = PT_REGS_PARM3_CORE(real_regs);

	bpf_trace_printk(fmt, sizeof(fmt), dirfd, pathname, flags);

	return 0;
}

char _license[] SEC("license") = "GPL";
