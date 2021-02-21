/* SPDX-License-Identifier: GPL-2.0 */

//#define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef INT_MAX
# define INT_MAX	((1l << 32) - 1)
#endif

struct syscalls_enter_sendmsg_args {
	__u64 __pad[2];
	__u64 fd;
	__u64 uservaddr;
	__u64 addrlen;
};

#define MAX_LENGTH 16

/* undefine `BPF_NO_PRESERVE_ACCESS_INDEX` to enable CO-RE.
 * However, there is `struct msg;` in vmlinux.h, so we can't
 * use name `struct msg`, otherwise it will result in
 * "call unknown#195896080" when use `bpf_get_current_comm()`
 * and `bpf_probe_read_user().
 */
struct bpf_msg {
	char comm[MAX_LENGTH];
	struct sockaddr uservaddr;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, IOC_PAGE_SIZE); // need page align
} ringbuf SEC(".maps");

static int id = -1;

//SEC("tracepoint/syscalls/sys_enter_openat")
SEC("tp/syscalls/sys_enter_connect")
int hello(struct syscalls_enter_sendmsg_args *ctx) {
	struct bpf_msg *val;

	val = bpf_ringbuf_reserve(&ringbuf, sizeof(*val), 0);
	if (!val)
		goto out;

	bpf_get_current_comm(val->comm, sizeof(val->comm));
	bpf_probe_read_user(&val->uservaddr,
			    sizeof(val->uservaddr), (void *)ctx->uservaddr);

	bpf_ringbuf_output(&ringbuf, val, sizeof(*val), 0);
	bpf_ringbuf_discard(val, 0);
out:
	return 0;
}

char _license[] SEC("license") = "GPL";
