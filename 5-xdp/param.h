#ifndef __PARAM_H__
#define __PARAM_H__

#include <stdbool.h>

enum {
	GETOPT_VAL_HELP = 257,
	GETOPT_VAL_VERBOSE,
	GETOPT_VAL_SKB_MODE,
	GETOPT_VAL_FORCE_LOAD,
	GETOPT_VAL_IFACE,
	GETOPT_VAL_MARK,
	GETOPT_VAL_CONF,
	GETOPT_VAL_WHITE_V4,
	GETOPT_VAL_WHITE_V6,
};

struct params {
	bool verbose;
	int flags;
	int ifindex;
	int mark;
	char *white_v4;
	char *white_v6;
};

int parse_options(int argc, char *argv[]);
extern struct params params;

#endif /* __PARAM_H__ */
