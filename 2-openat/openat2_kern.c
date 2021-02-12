/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/ptrace.h>

SEC("kprobe/do_sys_openat2")
int hello(struct pt_regs *ctx) {
	const int dirfd = PT_REGS_PARM1(ctx);
	const char *pathname = (char *)PT_REGS_PARM2(ctx);
	char fmt[] = "@dirfd='%d' @pathname='%s'";
	char msg[256];

	bpf_probe_read_user_str(msg, sizeof(msg), pathname);

	bpf_trace_printk(fmt, sizeof(fmt), dirfd, msg);

	return 0;
}

char _license[] SEC("license") = "GPL";
