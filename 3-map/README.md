---
title: eBPF系列三：eBPF map
date: 2021-02-15 15:59:51
tags: ["linux", "tracing tools", "eBPF"]
---

Blog Post: [ eBPF系列三: eBPF map](https://vvl.me/2021/02/eBPF-3-eBPF-map/)

迫于Linux eBPF文档过少，我边学习边把对其的理解记录下来，供后来者参考。
本文是eBPF系列的第三篇：eBPF map。

- 若对Linux tracing技术不清晰，可参考前置篇[the Overview of Linux Tracing Tools](/Appendix/1-the-Overview-of-Linux-Trace-Techonoly.md)
- 若对eBPF的工作流程不清晰，可参考[eBPF系列一：Hello eBPF](/1-hello/README.md)
- 篇二提供了一个采集系统调用openat2参数信息的例子，参见[eBPF系列二：例子——openat2](/2-openat/README.md)

## Introduction

先前在eBPF程序中向用户态程序传递信息使用的是`bpf_trace_printk()`，这种方式有局限性：它只能单向通信、参数最多为三个。另一种通信手段eBPF map，则没有上述限制，它被设计成key/value的形式，能够在用户态程序与内核态eBPF程序之间进行双向通信。官方描述[[1]]：

> Maps are a generic data structure for storage of different types
> of data.  They allow sharing of data between eBPF kernel
> programs, and also between kernel and user-space applications.

eBPF map在使用时有四个参数需要设置：

- type: eBPF map的类型，最基础的两类是array与hash，区别在于前者预分配空间，后者用时分配
- key\_size: key的字节大小
- value\_size: value的字节大小
- max\_entries: 元素的最大数量

eBPF map通过`bpf()`对用户态程序提供了五类cmd[[1]]；对于eBPF程序，bpf-helpers也列出了可用的bpf call[[2]]：

- `bpf()` cmd
  - `BPF_MAP_CREATE`
  - `BPF_MAP_LOOKUP_ELEM`
  - `BPF_MAP_UPDATE_ELEM`
  - `BPF_MAP_DELETE_ELEM`
  - `BPF_MAP_GET_NEXT_KEY`
- bpf call
  - 通用
    - `bpf_map_lookup_elem()`
    - `bpf_map_update_elem()`
    - `bpf_map_delete_elem()`
  - perf event array专用
    - `bpf_perf_event_{read, read_value}()`
    - `bpf_perf_event_output()`
  - ring buffer专用
    - `bpf_ringbuf_output()`
    - `bpf_ringbuf_reserve()`
    - `bpf_ringbuf_submit()`
    - `bpf_ringbuf_discard()`
    - `bpf_ringbuf_query()`

## Instance

下面实现了一个eBPF程序，它能够在每次调用到`vfs_read()`时，打印出当前OS的启动时间与进程名称。相关源码在[这里](https://github.com/time-river/Linux-eBPF-Learning/tree/main/3-map)。

### Example 1: HASH

这里采用的eBPF map的类型为`BPF_MAP_TYPE_HASH`，key是cpu id，value是`struct msg`，它用于记录向用户态抛出的数据信息。除了需要记录OS的启动时间与进程名称之外，还增加了一个变量`seq`用于体现eBPF map的双向通信特点：eBPF程序作为生产者，每次调用`vfs_read()`令`seq`增加1，eBPF用户态程序作为消费者，每次取得eBPF程序记录的数据后令`seq`减一，当`seq == 0`时清除该map中的key：

```c
struct msg {
	__s32 seq;
	__u64 cts;
	__u8 comm[MAX_LENGTH];
};

struct bpf_map_def SEC("maps") map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg),
	.max_entries = MAX_ENTRIES,
};

SEC("kprobe/vfs_read")
int hello(struct pt_regs *ctx) {
	int key = bpf_get_smp_processor_id() % MAX_ENTRIES;
	unsigned long cts = bpf_ktime_get_ns();
	struct msg *val, init_val = {0};

	val = bpf_map_lookup_elem(&map, &key);
	if (val) {
		val->seq += 1;
		val->cts = cts;
		bpf_get_current_comm(val->comm, sizeof(val->comm));
	} else {
		init_val.seq = 1;
		init_val.cts = cts;
		bpf_get_current_comm(init_val.comm, sizeof(init_val.comm));
		bpf_map_update_elem(&map, &key, &init_val, BPF_NOEXIST);
	}

	return 0;
}
```

> Note:
> 
> 1. 注意下变量`init_val`在声明的同时也对其进行了初始化操作，若不进行初始化，会报错："invalid indirect read from stack off -40+4 size 32"，这是在载入eBPF时特意做的检查，目的是阻止因内存未初始化导致的潜在安全风险[[3]]
> 2. `bpf_map_update_elem()`使用了flag `BPF_NOEXIST`，他能确保key对应的value不存在，对于array类型的eBPF map它不可用；这里也可使用`BPF_ANY`替代

`BPF_MAP_TYPE_HASH`类型的它是同步非阻塞的，也就是说没有办法得知有没有新的数据产生，需要轮询key用以检查是否有新数据的产生，因此用户态程序得这么写用于获取eBPF程序传递的信息：

```c
	for (int key = 0; ; key = (key+1)%nr_cpus) {
		if (!bpf_map_lookup_elem(map_fd[0], &key, &msg)) {
			fprintf(stdout, "%.4f: @seq=%d @comm='%s'\n",
				(float)msg.cts/1000000000ul, msg.seq, msg.comm);
			msg.seq -= 1;
			if (msg.seq <= 0)
				bpf_map_delete_elem(map_fd[0], &key);
			else
				bpf_map_update_elem(map_fd[0], &key, &msg, BPF_EXIST);
			memset(&msg, 0, sizeof(msg));
		}
	}
```

### Example 2: PERF\_EVENT\_ARRAY

有时候我们期望eBPF程序能够通知用户态程序数据准备好了，array、hash类型的eBPF map不满足此类使用场景，这时候就轮到`BPF_MAP_TYPE_PERF_EVENT_ARRAY`了。与普通hash、array类型有些不同，它没有`bpf_map_lookup_elem()`方法，使用的是`bpf_perf_event_output()`向用户态传递数据。它的`value_size`只能是`sizeof(u32)`，代表的是perf\_event的文件描述符；`max_entries`则是perf\_event的文件描述符数量。有关源码如下：

```c
struct msg {
	__s32 seq;
	__u64 cts;
	__u8 comm[MAX_LENGTH];
};

struct bpf_map_def SEC("maps") map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 0,
};

SEC("kprobe/vfs_read")
int hello(struct pt_regs *ctx) {
	unsigned long cts = bpf_ktime_get_ns();
	struct msg val = {0};
	static __u32 seq = 0;

	val.seq = seq = (seq + 1) % 4294967295U;
	val.cts = bpf_ktime_get_ns();
	bpf_get_current_comm(val.comm, sizeof(val.comm));

	bpf_perf_event_output(ctx, &map, 0, &val, sizeof(val));

	return 0;
}
```

> Note:
>
> 1. 这里的`seq`代表的是消息序列号
> 2. 若用户态不向内核态传递消息，PERF\_EVENT\_ARRAY map中的`max_entries`没有意义。该map向用户态传递的数据暂存在perf ring buffer中，而由`max_entries`指定的map存储空间存放的是perf\_event文件描述符，若用户态程序不向map传递perf\_event的文件描述符，其值可以为0。用户态程序使用`bpf(BPF_MAP_UPDATE_ELEM)`将由`sys_perf_event_open()`取得的文件描述符传递给eBPF程序，eBPF程序再使用`bpf_perf_event_{read, read_value}()`得到该文件描述符。于此有关的用法见linux kernel下的sample/bpf/tracex6_{user, kern.c}[[4]][[5]]）。

libbpf[[6]]提供了PERF\_EVENT\_ARRAY map在用户态开箱即用的API，它使用了epoll进行封装，仅需调用`perf_buffer__new()`、`perf_buffer__poll()`即可使用：

```c
static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size) {
	struct msg *msg = data;

	fprintf(stdout, "%.4f: @seq=%d @comm=%s\n",
		 (float)msg->cts/1000000000ul, msg->seq, msg->comm);
}

int main(int argc, char *argv[]) {
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;
	...

	pb_opts.sample_cb = print_bpf_output;
	pb = perf_buffer__new(map_fd, 8, &pb_opts);

	while (true) {
		perf_buffer__poll(pb, 1000);
		if (stop)
			break;
	}
	...
}
```

## Other eBPF maps

另一类与perf\_event\_array类似的eBPF map是`BPF_MAP_TYPE_RINGBUF`，它可以看作perf\_event\_array的加强版[[8]]。此外，还有一类`PERCPU`、`LRU`前缀的eBPF maps，顾名思义：`PERCPU`是per-cpu类型的map，能够减少eBPF程序中的锁竞争，而LRU则是采用了LRU替换算法的map。这些形形色色的map，都可以在linux源码中的samples/bpf[[9]]目录下找到对应的例子。

## Reference

- [man page: bpf][1]
- [man page: bpf-helpers][2]
- [stackoverflow: bpf how to inspect syscall arguments][3]
- [oracle blog: BPF In Depth: Communicating with Userspace][10]

[1]: https://man7.org/linux/man-pages/man2/bpf.2.html
[2]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
[3]: https://stackoverflow.com/questions/62441361/bpf-how-to-inspect-syscall-arguments
[4]: https://github.com/torvalds/linux/blob/v5.10/samples/bpf/tracex6_kern.c
[5]: https://github.com/torvalds/linux/blob/v5.10/samples/bpf/tracex6_user.c
[6]: https://github.com/torvalds/linux/tree/v5.10/tools/lib/bpf
[7]: https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h#L130
[8]: https://github.com/torvalds/linux/blob/v5.10/Documentation/bpf/ringbuf.rst
[9]: https://github.com/torvalds/linux/tree/master/samples/bpf
[10]: https://blogs.oracle.com/linux/notes-on-bpf-3
