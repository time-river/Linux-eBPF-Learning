/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_LENGTH	16

struct msg {
	__s32 seq;
	__u64 cts;
	__u8 comm[MAX_LENGTH];
};

struct bpf_map_def SEC("maps") map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	 /* `value_size` must be `sizeof(u32)`, which stand for
	  * perf_event file descriptor.
	  *
	  * If the map is just used to send message from kernelspace
	  * to userspace, `max_entries` could be zero, otherwise which
	  * value stands for the amount of perf_fd slots that is sent
	  * from userspace to kernelspace.
	  * One case `max_entries != 0`, tracex6_{kern, user}.c:
	  *  https://github.com/torvalds/linux/blob/v5.10/samples/bpf/tracex6_user.c
	  *  https://github.com/torvalds/linux/blob/v5.10/samples/bpf/tracex6_kern.c
	  */
	.value_size = sizeof(__u32),
	.max_entries = 0,
};

SEC("kprobe/vfs_read")
int hello(struct pt_regs *ctx) {
	unsigned long cts = bpf_ktime_get_ns();
	struct msg val = {0};
	static __u32 seq = 0;

	val.seq = seq = (seq + 1) % 4294967295U;
	val.cts = bpf_ktime_get_ns();
	bpf_get_current_comm(val.comm, sizeof(val.comm));

	bpf_perf_event_output(ctx, &map, 0, &val, sizeof(val));

	return 0;
}

char _license[] SEC("license") = "GPL";
