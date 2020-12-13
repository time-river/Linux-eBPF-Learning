/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/ptrace.h>

struct syscalls_enter_openat_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long syscall_nr;
	long dfd;
	long filename_ptr;
	long flags;
	long mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int hello(struct syscalls_enter_openat_args *ctx) {
	char fmt[] = "@dirfd='%d' @pathname='%s'";

	bpf_trace_printk(fmt, sizeof(fmt), ctx->dfd, (char *)ctx->filename_ptr);

	return 0;
}

char _license[] SEC("license") = "GPL";
