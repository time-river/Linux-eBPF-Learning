#ifndef __LOG_H__
#define __LOG_H__

#include <stdarg.h>

enum libbpf_print_level;
int print_all_levels(enum libbpf_print_level, const char *, va_list);
void ringbuf_run(void *arg);

void ringbuf_stop(void);
void free_ringbuf(void);

#endif /* __LOG_H__ */
