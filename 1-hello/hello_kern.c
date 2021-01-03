// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_clone")
int hello(struct pt_regs *ctx) {
	char msg[] = "Hello eBPF!";
	bpf_trace_printk(msg, sizeof(msg));
	return 0;
}

char _license[] SEC("license") = "GPL";
