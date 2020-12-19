/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#define MAX_LENGTH	16
#define MAX_ENTRIES	16

struct msg {
	unsigned int tgid;
	unsigned int pid;
	char comm[MAX_LENGTH];
	char msg[MAX_LENGTH];
};

struct bpf_map_def SEC("maps") map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg),
	.max_entries = MAX_ENTRIES,
};

SEC("kprobe/sys_clone")
int hello(struct pt_regs *ctx) {
	int key = bpf_get_smp_processor_id() % MAX_ENTRIES;
	unsigned long cts = bpf_ktime_get_ns();
	unsigned long id = bpf_get_current_pid_tgid();
	struct msg *val, init_val;
	char msg[MAX_LENGTH] = "Hello eBPF!";

	val = bpf_map_lookup_elem(&map, &key);
	if (val) {
		val->tgid = (id >> 32) & 0xffffffff;
		val->pid = id & 0xffffffff;
		bpf_get_current_comm(val->comm, sizeof(val->comm));
		memcpy(val->msg, msg, MAX_LENGTH);
	} else {
		init_val.tgid = (id >> 32) & 0xffffffff;
		init_val.pid = id & 0xffffffff;
		bpf_get_current_comm(init_val.comm, sizeof(init_val.comm));
		memcpy(init_val.msg, msg, MAX_LENGTH);
		bpf_map_update_elem(&map, &key, &init_val, BPF_NOEXIST);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
