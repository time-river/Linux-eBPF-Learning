/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifdef __x86_64__
#  define SYSCALL(SYS) "__x64_" #SYS
#elif defined(__aarch64__)
#  define SYSCALL(SYS) "__arm64_" #SYS
#elif defined(__s390x__)
#  define SYSCALL(SYS) "__s390x_" #SYS
#else
#  define SYSCALL(SYS)  #SYS
#endif

SEC("kprobe/" SYSCALL(sys_clone))
int hello(struct pt_regs *ctx) {
	char msg[] = "Hello eBPF!";
	bpf_trace_printk(msg, sizeof(msg));
	return 0;
}

char _license[] SEC("license") = "GPL";
