---
title: eBPF系列四：eBPF与CO-RE
date: 2021-02-24 21:48:35
tags: ["linux", "tracing tools", "eBPF"]
---

-Blog Post: [eBPF系列四: eBPF与CO-RE](https://vvl.me/2021/02/eBPF-4-eBPF-and-CO-RE/)

迫于Linux eBPF文档过少，我边学习边把对其的理解记录下来，供后来者参考。
本文是eBPF系列的第四篇：eBPF与CO-RE。

- 若对Linux tracing技术不清晰，可参考前置篇[the Overview of Linux Tracing Tools](/Appendix/1-the-Overview-of-Linux-Trace-Techonoly.md)
- 若对eBPF的工作流程不清晰，可参考[eBPF系列一：Hello eBPF](/1-hello/README.md)
- 篇二提供了一个采集系统调用openat2参数信息的例子，参见[eBPF系列二：例子——openat2](/2-openat/README.md)
- 篇三[eBPF系列三：eBPF map](/3-map/README.md)展示了eBPF map如何使用

## Introduction

bcc(BPF Compiler Collection)[[1]]能够简化eBPF程序的开发。但使用bcc编写的eBPF代码运行时编译，不仅需要kernel header，而且需携带llvm/clang相关的二进制。此外，因kernel struct的变更导致memory layout产生了变化，无法令编译生成的eBPF二进制运行在任意版本Linux kernel中，这就无法将eBPF二进制与用户态控制程序打包成二进制进行分发。

借助Linux kernel提供的BTF、bpftool与libbpf，能够将eBPF二进制与用户态控制程序封装至单个ELF中，实现CO-RE（Compile once, run everywhere），不必再担心因memory layout的变更导致eBPF二进制不再可用。只要kernel的eBPF功能具备相应的feature，它就能正常地运行在该kernel之上。并且借助BTF，编译时不必需要kernel header。[[2]][[3]]

编写能够CO-RE的eBPF代码步骤如下：

1. 执行`bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`导出当前运行的kernel定义的各类变量类型（v5.2添加该feature）
2. 在eBPF代码中声明的头文件如下[[4]]：

```c
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
```

4. 使用`bpftool gen skeleton <file> > <file>.skel.h`将编译生成的<file>转换为c文件（v5.6添加该feature）
5. 在用户态程序代码中`#include "<file>.skel.h"`，

`bpftool gen`的man page [[5]]上提供了一份示例代码。

Note: 

- llvm-10才提供了用于eBPF的attribute `__attribute__((preserve_access_index)`[[6]]，clang使用时需添加参数`-target bpf -g`
- 若eBPF中自定义的struct命名与kernel中的重复（比如`struct msg`），会导致该自定义的struct使用时出现问题

## Example

例子代码在[这里](https://github.com/time-river/Linux-eBPF-Learning/tree/main/4-CO-RE)。

实现了一个例子：追踪系统调用`connect()`的使用情况，打印使用者的进程名称目标的IPv4地址与端口。eBPF代码如下：

```c
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct syscalls_enter_sendmsg_args {
	__u64 __pad[2];
	__u64 fd;
	__u64 uservaddr;
	__u64 addrlen;
};

#define MAX_LENGTH 16

struct bpf_msg {
	char comm[MAX_LENGTH];
	struct sockaddr uservaddr;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, IOC_PAGE_SIZE);
} ringbuf SEC(".maps");

SEC("tp/syscalls/sys_enter_connect")
int hello(struct syscalls_enter_sendmsg_args *ctx) {
	struct bpf_msg *val;

	val = bpf_ringbuf_reserve(&ringbuf, sizeof(*val), 0);
	if (!val)
		goto out;

	bpf_get_current_comm(val->comm, sizeof(val->comm));
	bpf_probe_read_user(&val->uservaddr,
			    sizeof(val->uservaddr), (void *)ctx->uservaddr);

	bpf_ringbuf_submit(val, 0);
out:
	return 0;
}
```

Linux kernel v5.3介绍了定义eBPF map的新语法，称为BTF-defined maps，格式如`ringbuf`的定义，有两点变化：

1. `SEC(maps)`变为`SEC(.maps)`
2. 使用macro `__uint(type, xxx) / __type(key, xxx) / __type(value, xxx) / __uint(max_entries, xxx)`来替代原有的`.type=xxx / .key_size=xxx / .value=xxx / .max_entries=xxx`

原有的eBPF map写法被称为legancy mode。

这里使用了eBPF ring buffer，它在声明时仅需要提供type与max_entries信息，其中max_entries必须页对其。其提供了与`bpf_perf_event_output()`类似的API `bpf_ringbuf_output()`。这里使用了更高效的API组合`bpf_ringbuf_reserve() / bpf_ringbuf_submit()`。[[7]]。

至于`SEC("tp/syscalls/sys_enter_connect")`，是`SEC("tracepoint/syscalls/sys_enter_connect")`的简写，表明hook点是系统调用`connect()`。

用户态控制程序关键代码如下，它能够打印来自eBPF程序的消息：

```c
#include "connect_kern.skel.h"

static int print_bpf_output(void *ctx, void *data, size_t size) {
	struct bpf_msg *val = data;
	struct sockaddr_in *dest = (struct sockaddr_in *)&val->uservaddr;

	fprintf(stdout, ">> [%s]: connect '%s:%d'\n",
			val->comm,
			inet_ntoa(dest->sin_addr),
			dest->sin_port);
	return 0;
}

void setlimit(void) {
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);
}

int main(int argc, char *argv[]) {
	struct ring_buffer_opts rb_opts = {};
	...
	setlimit();

	skel = connect_kern__open_and_load();

	map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ringbuf");

	retval = connect_kern__attach(skel);

	rb = ring_buffer__new(map_fd, print_bpf_output, NULL, NULL);

	while (true) {
		ring_buffer__poll(rb, 1000);
		if (stop)
			break;
	}

	connect_kern__detach(skel);
	ring_buffer__free(rb);
	bpf_link__destroy(skel->links.hello);
cleanup:
	connect_kern__destroy(skel);
	return 0;
}
```

其中`connect_kern__{open_and_load, attach, detach, destroy}()`这些都是由`bpftool gen skeleton`自动生成的API，控制着eBPF程序的加载与使用，`ring_buffer__{new, poll, free}()`是libbpf使用epoll封装的eBPF ring buffer API。

编译及其结果如下：

```bash
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
$ clang -target bpf       \
         -nostdinc -isystem /usr/lib64/gcc/x86_64-suse-linux/10/include -I/usr/include -g      \
         -D__x86_64__ -O2 -emit-llvm -Xclang -disable-llvm-passes -c connect_kern.c -o - |     \
         opt -O2 -mtriple=bpf-pc-linux | llvm-dis |      \
         llc  -march=bpf -filetype=obj -o connect_kern.o
$ bpftool gen skeleton connect_kern.o > connect_kern.skel.h
$ clang -o connect connect.c -lbpf  -lelf
$ ldd connect
         linux-vdso.so.1 (0x00007ffcaa9ed000)
         libbpf.so.0 => /usr/lib64/libbpf.so.0 (0x00007f4f8f982000)
         libelf.so.1 => /usr/lib64/libelf.so.1 (0x00007f4f8f967000)
         libc.so.6 => /lib64/libc.so.6 (0x00007f4f8f798000)
         libz.so.1 => /usr/lib64/libz.so.1 (0x00007f4f8f77e000)
         /lib64/ld-linux-x86-64.so.2 (0x00007f4f8f9cd000)
```

## Reference

- [Linux Plumbers Conference 2018 BPF Microconference: Compile-Once Run-Everywhere BPF Programs? ][2]
- [Linux Kernel Developers' bpfconf 2019: BPF CO-RE (Compile Once - Run Everywhere)][3]
- [facebookmicrosites: HOWTO: BCC to libbpf conversion][4]
- [facebookmicrosites: BPF Portability and CO-RE][8]
- [facebookmicrosites: Enhancing the Linux kernel with BTF type information][9]
- [Brendan Gregg's Blog: BPF binaries: BTF, CO-RE, and the future of BPF perf tools][10]

## Epilogue

第一次接触eBPF是在19年年中，那时候只觉得这东西看起来好酷炫，有意愿却没有了解。去年9月先是使用bcc写了一个探测IP数据报文的程序，后在12月利用libbpf写了个开发者测试用例，开启了我的eBPF之旅。毕竟使用C写eBPF不如bcc简单，加之测试环境限制，并不能使用完整的libbpf，只能从Linux kernel中剥离libbpf代码使用，在12月份那次编码中栽了各种跟头，遂下决心系统地学习一下eBPF的编译与原理，偶然间看到了CO-RE这个概念，遂有了此系列文章。

eBPF系列文章至此暂告一段落，自我感觉了解了这么多足够入门了。当然还有许多概念并未展现或探究，比如xdp编程、四类`bpf()`枚举类型`enum bpf_cmd / enum bpf_map_type / enum bpf_prog_type / enum bpf_attach_type / enum bpf_link_type`的区别与联系、eBPF的指令格式与debug，等等等等。迫于时间所限与工作暂时用不到，不能慢慢琢磨了。来日方长，有缘再看:-)

[1]: https://github.com/iovisor/bcc
[2]: http://vger.kernel.org/lpc-bpf2018.html#session-2
[3]: http://vger.kernel.org/bpfconf2019.html#session-2
[4]: https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html
[5]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
[6]: https://clang.llvm.org/docs/AttributeReference.html#preserve-access-index
[7]: https://nakryiko.com/posts/bpf-ringbuf/
[8]: https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
[9]: https://facebookmicrosites.github.io/bpf/blog/2018/11/14/btf-enhancement.html
[10]: http://www.brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html
