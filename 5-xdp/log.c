#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>

#include <linux/in6.h>

#include "param.h"
#include "ebpf.h"

static struct ring_buffer *rb;
static bool rb_stop;

void ringbuf_stop(void) {
	rb_stop = true;
}

void free_ringbuf(void) {
	if (rb != NULL)
		ring_buffer__free(rb);
}

static int print_bpf_output(void *ctx, void *data, size_t size) {
	const char *family[] = {
		[AF_INET] = "AF_INET",
		[AF_INET6] = "AF_INET6",
	};
	const char *action[] = {
		[LPM_PASS] = "LPM_PASS",
		[LPM_MARK] = "LPM_MARK",
	};
	char src[INET6_ADDRSTRLEN] = { 0 }, dst[INET6_ADDRSTRLEN] = { 0 };
	struct bpf_msg *val = data;

	inet_ntop(val->family, val->src, src, sizeof(src));
	inet_ntop(val->family, val->dst, dst, sizeof(dst));

	fprintf(stdout, ">> family %s src %s dst %s proto %d",
			family[val->family], src, dst, val->proto);
	if (val->found) {
		switch (val->action) {
		case LPM_PASS:
			fprintf(stdout, " found %s\n", action[val->action]);
			break;
		case LPM_MARK:
			fprintf(stdout, " found %s mark 0x%x\n", action[val->action], val->mark);
			break;
		default:
			fprintf(stdout, "\n");
			break;
		}
	} else {
		fprintf(stdout, " not found\n");
	}

	fflush(stdout); /* flush to display immediately */

	return 0;
}

void ringbuf_run(void *arg) {
	int fd = *(int *)arg;

	rb = ring_buffer__new(fd, print_bpf_output, NULL, NULL);
	if (rb == NULL) {
		fprintf(stderr, "ERROR: failed to setup bpf ring_buffer!\n");
		exit(EXIT_FAILURE);
	}

	while (!rb_stop) {
		ring_buffer__poll(rb, 1000);
	}

	return;
}

int print_all_levels(enum libbpf_print_level leve,
				const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}
