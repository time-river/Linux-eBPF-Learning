/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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

// The value size of `BPF_MAP_TYPE_PERF_EVENT_ARRAY` is only `sizeof(u32)`
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, struct msg);
	/* for perf_event_array, it isn't necessary to set max entries
	 * parameter.
	 */
} perf_map SEC(".maps");

static int id = -1;

SEC("tracepoint/syscalls/sys_enter_openat")
int hello(struct syscalls_enter_openat_args *ctx) {
	struct msg val = {0};

	id = (id + 1) % INT_MAX;
	val.id = id;
	val.pid = ctx->common_pid;
	val.flags = ctx->flags;
	bpf_get_current_comm(val.comm, sizeof(val.comm));
	memcpy(val.file, (void *)ctx->filename_ptr, sizeof(val.file));

	bpf_perf_event_output(ctx, &perf_map, 0, &val, sizeof(val));

	return 0;
}

char _license[] SEC("license") = "GPL";
