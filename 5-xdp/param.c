#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>

#include <net/if.h>
#include <linux/if_link.h>

#include "param.h"

struct params params = {
	.verbose = true,
	.flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	.ifindex = -1,
	.mark = 0x13462f4,
};

static void usage(char *name) {
	printf("\n");
	printf(
		"  Usage:\n"
		"    %s\n\n"
		"	-s, --skb-mode		use skb mode instead native mode.\n"
		"	-f, --force-load	force loading eBPF program.\n"
		"	-i, --interface		the interface which loads the eBPF program.\n"
		"	--white-v4		the IPv4 whitelist.\n"
		"	--white-v6		the IPv6 whitelist.\n"
		"	-m, --mark		the skb meta mark tagged by eBPF program, hex format, non-zero, default is 0x13462f4.\n"
		"	-c, --conf		the configuration file path.\n"
		"	-v, --verbose		verbose mode.\n"
		"	-h, --help		print this message.\n",
		name);
}

static int parse_conf(char *filepath) { return 0; }

int parse_options(int argc, char *argv[]) {
	const struct option options[] = {
		{ "help", no_argument, NULL, GETOPT_VAL_HELP },
		{ "verbose", no_argument, NULL, GETOPT_VAL_VERBOSE },
		{ "skb-mode", no_argument, NULL, GETOPT_VAL_SKB_MODE },
		{ "force-load", no_argument, NULL, GETOPT_VAL_FORCE_LOAD },
		{ "interface", required_argument, NULL, GETOPT_VAL_IFACE },
		{ "white-v4", required_argument, NULL, GETOPT_VAL_WHITE_V4 },
		{ "white-v6", required_argument, NULL, GETOPT_VAL_WHITE_V6 },
		{ "mark", required_argument, NULL, GETOPT_VAL_MARK },
		{ "conf", required_argument, NULL, GETOPT_VAL_CONF },
		{ NULL, 0, NULL, 0 }
	};
	int c, mark;

	while ((c = getopt_long(argc, argv, "hvsfi:m:c:",
					options, NULL)) != -1) {
		switch (c) {
			case GETOPT_VAL_VERBOSE:
			case 'v':
				params.verbose = true;
				break;
			case GETOPT_VAL_SKB_MODE:
			case 's':
				params.flags |= XDP_FLAGS_SKB_MODE;
				break;
			case GETOPT_VAL_FORCE_LOAD:
			case 'f':
				params.flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
				break;
			case GETOPT_VAL_IFACE:
			case 'i':
				params.ifindex = if_nametoindex(optarg);
				break;
			case GETOPT_VAL_MARK:
			case 'm':
				mark = strtol(optarg, NULL, 16);
				if (mark == 0) {
					fprintf(stderr, "WARN: mark shouldn't be zero,"
							" use default value\n");
					exit(EXIT_FAILURE);
				} else
					params.mark = mark;
				break;
			case GETOPT_VAL_CONF:
			case 'c':
				if (parse_conf(optarg) != 0) {
					fprintf(stderr, "parse '%s' failed\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			case GETOPT_VAL_WHITE_V4:
				if (access(optarg, R_OK) != 0) {
					fprintf(stderr, "ERR: can't read file %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				params.white_v4 = strdup(optarg);
				break;
			case GETOPT_VAL_WHITE_V6:
				if (access(optarg, R_OK) != 0) {
					fprintf(stderr, "ERR: can't read file %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				params.white_v6 = strdup(optarg);
				break;
			case GETOPT_VAL_HELP:
			case 'h':
			default:
				usage(argv[0]);
				exit(EXIT_SUCCESS);
				break;
		}
	}

	if (params.ifindex == -1) {
		fprintf(stderr, "WARN: ifname is needed!\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
