/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#ifndef INT_MAX
# define INT_MAX	((1l << 32) - 1)
#endif

struct syscalls_enter_openat_args {
	unsigned short common_type;
	unsigned char comon_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long syscall_nr;
	long dfs;
	long filename_ptr;
	long flags;
	long mode;
};

#ifndef memcpy
# define memcpy(dest, src, n)	__builtin_memcpy((dest), (src), (n))
#endif

#define MAX_LENGTH 64

struct msg {
	int id;
	int pid;
	int flags;
	char comm[MAX_LENGTH];
	char file[MAX_LENGTH];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<12); // need page align
} ringbuf SEC(".maps");

static int id = -1;

//SEC("tracepoint/syscalls/sys_enter_openat")
SEC("tp/syscalls/sys_enter_openat")
int hello(struct syscalls_enter_openat_args *ctx) {
	struct msg *val;

	val = bpf_ringbuf_reserve(&ringbuf, sizeof(*val), 0);
	if (!val)
		goto out;

	val->id = id = (id + 1) % INT_MAX;
	/* can't use `PROBE_CORE_READ()` because the `typeof(ctx)` is defined by
	 * ourself.
	 *
	 * access rules: kernel/bpf/bpf_trace.c
	 *   func: tp_prog_is_valid_access()
	 *           if (off < sizeof(void *) || off >= PERF_MAX_TRACE_SIZE)
	 *             return false;
	 */
	// we can't access it directly because of `sizeof(ctx->common_pid < sizeof(void *)`
	bpf_probe_read_kernel(&val->pid, sizeof(val->pid), &ctx->common_pid);
	// we can access it directly because of `size(ctx->flags) == sizeof(void *)`
	val->flags = ctx->flags;
	bpf_get_current_comm(val->comm, sizeof(val->comm));
	bpf_probe_read_user_str(val->file, sizeof(val->file), (void *)ctx->filename_ptr);

	bpf_ringbuf_output(&ringbuf, val, sizeof(*val), 0);
	bpf_ringbuf_discard(val, 0);
out:
	return 0;
}

char _license[] SEC("license") = "GPL";
