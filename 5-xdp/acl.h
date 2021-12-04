#ifndef __ACL_H__
#define __ACL_H__

#include <netinet/in.h>

struct addr_info {
	union {
		struct bpf_lpm_trie_key key;
		struct {
			int bits;
			union {
				char v4[sizeof(in_addr_t)];
				char v6[sizeof(struct in6_addr)];
			};
		};
	};
};

int parse_and_load_acl(const char *filename, uint8_t family, int fd, int mark);
int load_default_ipv4_acl(int fd, int mark);
int load_default_ipv6_acl(int fd, int mark);

static inline int load_ipv4_acl(const char *filename, int fd, int mark) {
	int retval = load_default_ipv4_acl(fd, mark);

	return retval != 0 ? retval : parse_and_load_acl(filename, AF_INET, fd, mark);
}

#endif /* __ACL_H__ */
