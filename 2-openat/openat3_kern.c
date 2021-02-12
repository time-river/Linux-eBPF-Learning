/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/sys_openat")
int hello(struct pt_regs *ctx) {
	char fmt[] = "@dirfd='%d' @pathname='%s'";
	struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	int dirfd = PT_REGS_PARM1_CORE(real_regs);
	char *pathname = (char *)PT_REGS_PARM2_CORE(real_regs);

	bpf_trace_printk(fmt, sizeof(fmt), dirfd, pathname);

	return 0;
}

char _license[] SEC("license") = "GPL";
