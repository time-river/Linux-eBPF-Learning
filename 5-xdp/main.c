/*
 * Usage example:
 *  # ./xdp -i eth0 --verbose --white-v4 china_ip_list.txt --mark 42 -s
 *  # iptables -I INPUT -m mark --mark 0x42
 *  # iptables -nvL
 *
 * If the network works, you will see the `pkts` changing showing by `iptables -nvL`.
 */

#define DEBUG
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <net/if.h>

#include <linux/if_link.h>
#include <bpf/bpf.h>

#include "param.h"
#include "log.h"
#include "acl.h"
#include "ebpf_kern.skel.h"

static void exit_handler(int sig) {
	ringbuf_stop();
}

static void setlimit(void) {
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
		fprintf(stderr, "setrlimit failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[]) {
	struct ebpf_kern *skel;
	int xdp_prog_fd, tc_prog_fd, lpm_v4_map_fd, ringbuf_fd;
	int retval = -1;
	struct bpf_prog_info info = {};
	unsigned int info_len = sizeof(info);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);

	parse_options(argc, argv);
	tc_hook.ifindex = params.ifindex;

	setlimit();

	skel = ebpf_kern__open();
	if (!skel) {
		fprintf(stderr, "ebpf_kern__open failed: %s\n", strerror(errno));
		return -1;
	}

	if (params.verbose) {
		libbpf_set_print(print_all_levels);
		skel->bss->verbose = true;
	}

	retval = bpf_map__resize(skel->maps.lpm_v4_map, 1<<16);
	if (retval) {
		fprintf(stderr, "bpf_map__resize failed: %s\n", strerror(errno));
		goto destroy;
	}

	retval = ebpf_kern__load(skel);
	if (retval) {
		fprintf(stderr, "ebpf_kern__load failed: %s\n", strerror(errno));
		goto destroy;
	}

	retval = ebpf_kern__attach(skel);
	if (retval) {
		fprintf(stderr, "ebpf_kern__attach failed: %s\n", strerror(errno));
		goto destroy;
	}

	signal(SIGINT, exit_handler);
	signal(SIGTERM, exit_handler);

	xdp_prog_fd = bpf_program__fd(skel->progs.xdp__mark_prog);
	if (xdp_prog_fd < 0) {
		fprintf(stderr, "bpf_program__fd(xdp__mark_prog) failed: %s\n", strerror(errno));
		goto detach;
	}

	tc_prog_fd = bpf_program__fd(skel->progs.classifier__mark_prog);
	if (tc_prog_fd < 0) {
		fprintf(stderr, "bpf_program__fd(classifier__mark_prog) failed: %s\n", strerror(errno));
		goto detach;
	}
	tc_opts.prog_fd = tc_prog_fd;

	lpm_v4_map_fd = bpf_map__fd(skel->maps.lpm_v4_map);
	if (lpm_v4_map_fd < 0) {
		fprintf(stderr, "bpf_map__fd(lpm_v4_map) failed: %s\n", strerror(errno));
		goto detach;
	}

	ringbuf_fd = bpf_map__fd(skel->maps.ringbuf);
	if (ringbuf_fd < 0) {
		fprintf(stderr, "bpf_map__fd(ringbuf) failed: %s\n", strerror(errno));
		goto detach;
	}

	if (params.white_v4 != NULL
			&& load_ipv4_acl(params.white_v4, lpm_v4_map_fd, params.mark) != 0) {
		fprintf(stderr, "load IPv4 acl failed\n");
		goto detach;
	}

	if (bpf_set_link_xdp_fd(params.ifindex, xdp_prog_fd, params.flags) < 0) {
		fprintf(stderr, "bpf_set_link_xdp_fd failed: %s\n", strerror(errno));
		if (errno == EOPNOTSUPP) {
			fprintf(stderr, "try use skb-mode, add `-s` option\n");
		}
		goto detach;
	}

	if (bpf_tc_hook_create(&tc_hook) != 0 && errno != EEXIST) {
		fprintf(stderr, "bpf_tc_hook_create failed: %s\n", strerror(errno));
		goto unset_xdp;
	} else if (errno == EEXIST)
		fprintf(stdout, "tc hook has been created\n");

	if (bpf_tc_attach(&tc_hook, &tc_opts) != 0) {
		fprintf(stderr, "bpf_tc_attach failed: %s\n", strerror(errno));
		if (errno == EEXIST) {
			fprintf(stdout, "bpf_tc_attach attach failed: File exists.\n"
					"Try to execute `# tc filter del dev <dev> ingress` to delete all filter\n");
		}
		goto unset_tc_hook;
	}


	ringbuf_run(&ringbuf_fd);

unset_tc_hook:
	if (bpf_tc_hook_destroy(&tc_hook) != 0)
		fprintf(stderr, "bpf_tc_hook_destroy failed: %s\n", strerror(errno));
unset_xdp:
	if (bpf_set_link_xdp_fd(params.ifindex, -1, params.flags) < 0)
		fprintf(stderr, "failed to detach xdp program: %s\n", strerror(errno));
detach:
	ebpf_kern__detach(skel);
	free_ringbuf();
destroy:
	ebpf_kern__destroy(skel);
	return retval;
}
