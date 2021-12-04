#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>

#include "acl.h"
#include "ebpf.h"

static int load_acl(int fd, struct addr_info *info, int mark) {
	struct bpf_lpm_trie_key *key = &info->key;
	struct trie_value val = {
		.mark = mark,
		.action = LPM_MARK,
	};

	return bpf_map_update_elem(fd, key, &val, BPF_ANY);
}

int parse_and_load_acl(const char *filename, uint8_t family, int fd, int mark) {
	size_t addr_len = family == AF_INET ? sizeof(in_addr_t) : sizeof(struct in6_addr);
	FILE *fp = fopen(filename, "r");
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;

	if (fp == NULL)
		return -1;

	while ((nread = getline(&line, &len, fp) != -1)) {
		struct addr_info addr;

		if (line == NULL)
			continue;

		line[strlen(line)-1] = '\0';
		addr.bits = inet_net_pton(family, line, addr.v4, addr_len);
		if (addr.bits <= 0) {
			fprintf(stderr, "wrong format: %s\n", line);
			continue;
		}

		if (load_acl(fd, &addr, mark) != 0) {
			fprintf(stderr, "error\n");
			free(line);
			return -1;
		}
	}

	free(line);
	return 0;
}

int load_default_ipv4_acl(int fd, int mark) {
	struct addr_info ip4[] = {
		{ .bits =  8, .v4 = { 0x7f, 0x00, 0x00, 0x00 }, }, /* 127.0.0.0/8 */
		{ .bits = 16, .v4 = { 0xa9, 0xfe, 0x00, 0x00 }, }, /* 169.254.0.0/16 */
		{ .bits = 32, .v4 = { 0xff, 0xff, 0xff, 0xff }, }, /* 255.255.255.255/32 */
		{ .bits = 16, .v4 = { 0xc0, 0xa8, 0x00, 0x00 }, }, /* 192.168.0.0/16 */
	};

	for (int i = 0; i < sizeof(ip4)/sizeof(ip4[0]); i++) {
		if (load_acl(fd, ip4+i, mark) != 0) {
			fprintf(stderr, "error\n");
			return -1;
		}
	}

	return 0;
}
