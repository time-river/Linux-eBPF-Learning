/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/ptrace.h>

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

typedef __kernel_size_t size_t;
typedef __kernel_loff_t loff_t;
typedef __u32 u32;

struct msg {
	char buf[32];
	size_t count;
	loff_t pos;
};

struct bpf_map_def SEC("maps") map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = 2,
};

SEC("kprobe/vfs_write")
int hello(struct pt_regs *ctx) {
	char *buf = (char *)PT_REGS_PARM2(ctx);
	size_t count = PT_REGS_PARM3(ctx);
	loff_t *pos = (loff_t *)PT_REGS_PARM4(ctx);
	struct msg data = {0};

	bpf_probe_read_user_str(data.buf, sizeof(data.buf)-1, buf);
	data.count = count;
	bpf_probe_read_kernel(&data.pos, sizeof(data.pos), pos);

	bpf_perf_event_output(ctx, &map, 0, &data, sizeof(data));

	return 0;
}

char _license[] SEC("license") = "GPL";
