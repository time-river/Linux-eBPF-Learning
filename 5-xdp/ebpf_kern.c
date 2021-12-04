#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "ebpf.h"

const bool _; /* unused, bugfix for skel to prevent the compilier reports error */
bool verbose;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct trie_key_4));
	__uint(value_size, sizeof(struct trie_value));
	__uint(max_entries, 1<<16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_v4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct trie_key_6));
	__uint(value_size, sizeof(struct trie_value));
	__uint(max_entries, 1<<16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_v6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, IOC_PAGE_SIZE);
} ringbuf SEC(".maps");

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end,
			     __be32 *src, __be32 *dst)
{
	struct iphdr *iph = data + nh_off;

	if ((void *)(iph + 1) > data_end)
		return 0;

	*src = iph->saddr;
	*dst = iph->daddr;
	return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end,
				struct in6_addr *src, struct in6_addr *dst)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if ((void *)(ip6h + 1) > data_end)
		return 0;

	__builtin_memcpy(src, &ip6h->saddr, sizeof(struct in6_addr));
	__builtin_memcpy(dst, &ip6h->daddr, sizeof(struct in6_addr));
	return ip6h->nexthdr;
}

static inline int xdp_mark(struct xdp_md *ctx, __u32 mark)
{
	struct meta_info *meta;
	void *data;
	int retval;

	retval = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (retval < 0)
		return XDP_ABORTED;

	data = (void *)(unsigned long)ctx->data;
	meta = (void *)(unsigned long)ctx->data_meta;

	/* Check data_meta have room for meta_info struct */
	if ((void *)(meta + 1) > data)
		return XDP_ABORTED;

	meta->mark = mark;

	return XDP_PASS;
}

SEC("xdp_mark")
int xdp__mark_prog(struct xdp_md *ctx)
{
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(unsigned long)ctx->data_end;
	struct ethhdr *eth = data;
	int retval = XDP_PASS;
	struct trie_value *value;
	struct bpf_msg msg = { 0 };
	u16 h_proto;
	u32 ipproto;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if ((data + nh_off) > data_end)
		return XDP_DROP;
	h_proto = eth->h_proto;

	if (h_proto != bpf_htons(ETH_P_IP) && h_proto != bpf_htons(ETH_P_IPV6))
		return XDP_PASS;

	if (h_proto == bpf_htons(ETH_P_IP)) {
		__be32 *src = &msg.src_v4, *dst = &msg.dst_v4;
		struct trie_key_4 key = { .prefixlen = 32 };

		ipproto = parse_ipv4(data, nh_off, data_end, src, dst);
		if (__builtin_expect(ipproto == 0, false))
			return XDP_PASS;

		msg.family = AF_INET;

		key.data[0] = *dst & 0xff;
		key.data[1] = (*dst >> 8) & 0xff;
		key.data[2] = (*dst >> 16) & 0xff;
		key.data[3] = (*dst >> 24) & 0xff;

		/* Look up in the trie for lpm*/
		value = bpf_map_lookup_elem(&lpm_v4_map, &key);
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		unsigned char *src = msg.src_v6;
		unsigned char *dst = msg.dst_v6;
		struct trie_key_6 key = { .prefixlen = 128 };
		void *lpm = &lpm_v6_map;

		ipproto = parse_ipv6(data, nh_off, data_end, (void *)src, (void *)dst);
		if (__builtin_expect(ipproto == 0, false))
			return XDP_PASS;

		msg.family = AF_INET6;

		/* 
		 * Can't use `__builtin_memcmp` directly because of the
		 * non-inline implementation.
		 */
		if (key.data[0] == 0xff
				&& key.data[1] == 0xff
				&& key.data[2] == 0xff
				&& key.data[4] == 0xff
				&& key.data[5] == 0xff
				&& key.data[6] == 0xff
				&& key.data[7] == 0xff
				&& key.data[8] == 0xff
				&& key.data[9] == 0xff
				&& key.data[10] == 0xff
				&& key.data[11] == 0xff) {
			lpm = &lpm_v4_map;
			key.data[0] = dst[12] & 0xff;
			key.data[1] = dst[13] & 0xff;
			key.data[2] = dst[14] & 0xff;
			key.data[3] = dst[15] & 0xff;
		} else
			__builtin_memcpy(key.data, dst, sizeof(key.data));

		/* Look up in the trie for lpm*/
		value = bpf_map_lookup_elem(lpm, &key);
	}

	if (value) {
		switch (value->action) {
		case LPM_MARK:
			retval = xdp_mark(ctx, value->mark);
			break;
		default:
			retval = XDP_PASS;
			break;
		}
		msg.found = true;
		msg.action = value->action;
		msg.mark = value->mark;
	} else
		msg.found = false;

	msg.proto = ipproto;

	/*
	 * Set ringbuf outmsg msg here. It's impossible to write code like the following:
	 * ```
	 * 	struct bpf_msg *msg = NULL;
	 *
	 * 	if (__builtin_expect(verbose, false))
	 * 		msg = bpf_ringbuf_reserve(&ringbuf, sizeof(msg), 0); # don't check msg value here, delay check
	 *
	 * 	do else... (include `bpf_map_lookup_elem()` bpf call)
	 *
	 * 	if (__builtin_expect(verbose, false) && msg != NULL) # check msg value here
	 * 		bpf_ringbuf_submit(msg, BPF_RB_FORCE_WAKEUP);
	 * ```
	 *
	 * Currently (2021.11.20, v5.14), eBPF verifier is folly (or it's a bug): after
	 * `bpf_map_lookup_elem()` is called, the program will exit without calling
	 * `bpf_ringbuf_submit()`. Then, eBPF verifier thinks it's illegal, reports:
	 * ```
	 * 	Unreleased reference id=2 alloc_insn=21
	 * ```
	 *   Note: `alloc_insn=21` is `21: (85) call bpf_ringbuf_reserve#131`
	 *
	 * Reason, I guess: eBPF verifier will emit all posiible path during verification,
	 * I don't check the `msg` value after calling `bpf_ringbuf_reserve()` and do
	 * exception handling, so clang won't generate the freeing code for some branch.
	 * However, eBPF verifier checks the acquiring function calling, but no releasing
	 * function calling, then reports the exception :-(
	 */
	if (__builtin_expect(verbose, false))
		bpf_ringbuf_output(&ringbuf, &msg, sizeof(msg), BPF_RB_FORCE_WAKEUP);

	return retval;
}

/* xdp program can't mark skb, so set mark here. Then we could use
 * ```
 *   # iptables -I INPUT -m mark --mark <mark>
 *   # iptables -nvL
 * ```
 * to watch the marking packets.
 */
SEC("classifier_mark")
int classifier__mark_prog(struct __sk_buff *skb)
{
	void *data      = (void *)(unsigned long)skb->data;
	void *data_end  = (void *)(unsigned long)skb->data_end;
	struct meta_info *meta = (void *)(unsigned long)skb->data_meta;

	/* Check XDP gave us some data_meta */
	if ((void *)(meta + 1) <= data)
		skb->mark = meta->mark; /* Transfer XDP-mark to SKB-mark */

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
