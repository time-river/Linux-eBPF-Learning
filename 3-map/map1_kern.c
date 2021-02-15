/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_LENGTH	16
#define MAX_ENTRIES	16

struct msg {
	__s32 seq;
	__u64 cts;
	__u8 comm[MAX_LENGTH];
};

struct bpf_map_def SEC("maps") map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg),
	.max_entries = MAX_ENTRIES,
};

SEC("kprobe/vfs_read")
int hello(struct pt_regs *ctx) {
	int key = bpf_get_smp_processor_id() % MAX_ENTRIES;
	unsigned long cts = bpf_ktime_get_ns();
	/* `init_val` without `= {0}`, error: "invalid indirect
	 *  read from stack off -40+4 size 32", reason:  reading
	 *  uninitialised memory from the kernel introduces a
	 *  security risk.
	 *
	 *  link:
	 *    https://stackoverflow.com/questions/62441361/bpf-how-to-inspect-syscall-arguments
	 */
	struct msg *val, init_val = {0};

	val = bpf_map_lookup_elem(&map, &key);
	if (val) {
		val->seq += 1;
		val->cts = cts;
		bpf_get_current_comm(val->comm, sizeof(val->comm));
	} else {
		init_val.seq = 1;
		init_val.cts = cts;
		bpf_get_current_comm(init_val.comm, sizeof(init_val.comm));
		bpf_map_update_elem(&map, &key, &init_val, BPF_NOEXIST);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
