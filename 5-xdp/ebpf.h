#ifndef __EBPF_H__
#define __EBPF_H__

#include <stdbool.h>

#ifndef ETH_P_IP
# define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#endif

#ifndef ETH_P_IPV6
# define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#endif

#ifndef AF_INET
# define AF_INET	2	/* IP protocol family. */
#endif

#ifndef AF_INET6
# define AF_INET6	10	/* IP version 6. */
#endif

#ifndef TC_ACT_OK
# define TC_ACT_OK		0
#endif

/* The struct must be 4 byte aligned, which here is enforced by the
 * struct __attribute__((aligned(4))).
 */
struct meta_info {
	unsigned int mark;
} __attribute__((aligned(4)));

enum lpm_action {
	LPM_PASS = 1024,
	LPM_MARK,
};

struct trie_value {
	enum lpm_action action;
	unsigned int mark;
};

/* the tmpl of bpf_trie_key is `struct bpf_lpm_trie_key` */
struct trie_key_4 {
	unsigned prefixlen; /* up to 32 for AF_INET */
	unsigned char data[4]; /* AF_INET data */
};

struct trie_key_6 {
	unsigned prefixlen; /* up to 128 for AF_INET6 */
	unsigned char data[16]; /* AF_INET6 data */
};

struct bpf_msg {
	unsigned char family;
	union {
		unsigned char src[0];
		unsigned int src_v4;
		unsigned char src_v6[16];
	};
	union {
		unsigned char dst[0];
		unsigned int dst_v4;
		unsigned char dst_v6[16];
	};
	bool found;
	enum lpm_action action;
	unsigned int mark;
	unsigned char proto;
};

#endif /* __EBPF_H__ */
