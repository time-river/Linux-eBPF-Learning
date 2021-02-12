---
title: eBPF系列一：Hello eBPF
date: 2021-01-03 15:14:52
tags: ["linux", "tracing tools", "eBPF"]
---
# Hello eBPF

Blog Post: [eBPF系列一：Hello eBPF](https://vvl.me/2021/01/eBPF-1-Hello-eBPF/)

迫于Linux eBPF文档过少，我边学习边把对其的理解记录下来，供后来者参考。
本文是eBPF系列的第一篇：hello eBPF。
若对Linux tracing技术不清晰，可参考前置篇[the Overview of Linux Tracing Tools](/Appendix/1-the-Overview-of-Linux-Trace-Techonoly.md)。

## Overview

先写了一个eBPF例子，它能够在每次进行系统调用`clone()`时打印一行`Hello eBPF!`，并说明eBPF程序怎么从源码到执行的。

再写了点eBPF执行的内幕，包括两点：

1. eBPF怎么检查内存访问的
2. eBPF程序怎么进行BPF helper function call

## an Example

这些源码在[这里](https://github.com/time-river/Linux-eBPF-Learning/tree/main/1-hello)。

### eBPF program

一个简单的eBPF程序如下，它能够在每次进行系统调用`clone()`时打印一行`Hello eBPF!`：

```c
// hello_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_clone")
int hello(struct pt_regs *ctx) {
	char msg[] = "Hello eBPF!";
	bpf_trace_printk(msg, sizeof(msg));
	return 0;
}

char _license[] SEC("license") = "GPL";
```

在该代码中，`SEC(NAME)`定义在头文件`bpf/bpf_helpers.h`中，为`__attribute__((section(NAME), used))`，即把该变量、函数放在ELF文件中名为*NAME*的section中。`_license`定义了该eBPF程序的license类型，在eBPF程序加载的过程中会校验license是否为GPL[[1]]兼容的。`hello()`调用了`bpf_trace_printk()`将msg写入tracefs的ring buffer中，`bpf_trace_printk()`最多可接收三个参数进行格式化输出。`SEC("kprobe/sys_clone")`声明`hello()`使用kprobe hook至系统调用`clone()`的函数入口处。

当前（2021.01.03）可用clang+llvm编译eBPF程序，其他的编译器，比如GCC、rust等，亦在添加对eBPF的支持中[[2]][[3]]。clang把eBPF程序翻译为中间语言（IR）是LLVM的object(参数`-c -emit-llvm`），再通过llc编译、链接成target为bpf的ELF程序（参数`-march=bpf -filetype=obj`）。这里还使用了`-O2`参数对其进行优化。

```bash
$ clang -O2 -emit-llvm -c hello_kern.c -o - | \
        llc  -march=bpf -filetype=obj -o hello_kern.o
$ readelf -a hello_kern.o
ELF Header:
...
Machine:                           Linux BPF
...
Section Headers:
...
[ 3] kprobe/sys_clone  PROGBITS         0000000000000000  00000040
...
[ 5] license           PROGBITS         0000000000000000  000000a4
...
Symbol table '.symtab' contains 5 entries:
...
3: 0000000000000000     4 OBJECT  GLOBAL DEFAULT    5 _license
4: 0000000000000000    88 FUNC    GLOBAL DEFAULT    3 hello
```

### Userspace Helper Program

仅有eBPF程序还不够，需要用户态程序把eBPF程序注入内核、并从内核中读取相关的信息。Linux提供了libbpf[[4]]（即`tools/lib/bpf`）供用户态程序调用，它有两层level：封装系统调用`bpf()`的bpf.c，及解析bpf target格式的ELF文件的libbpf.c。Linux亦在`sample/bpf`下提供了一些eBPF示例，后缀`_kern.c`代表eBPF程序，`_user.c`代表用户态程序，也实现了简化版libbpf.c的bpf_load.c。

对于hello_kern.o来讲，使其工作需要这几个步骤：

1. 解析ELF文件，解析出函数`hello()`指令，调用`bpf(BPF_PROG_LOAD)`将其注入内核，取得prog_fd
2. 生成kprobe `clone()`的hook point，使用`perf_event_open()`获取pfd，该pfd与hook point相关联
3. 使用`ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd)`将该eBPF程序与perf event绑定
4. 使用`ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0)`使能该perf event
5. 读取tracefs中的trace_pipe获取来自eBPF程序的msg

> Note:  
> 原则上kprobe能够hook的func，在config `CONFIG_KALLSYMS_ALL=y`的情况下，全都记录在`/proc/kallsyms`中。对于kprobe:
>
> - bpf_load.c采用的是`echo 'p:<name> <func>' <tracefs>/kprobe_events`方式生成名为`<name>`的`<func>` hook point，再通过`perf_event_open()`获取关联着该hook point的pfd。因此尽管在`/proc/kallsyms`中没有名为`sys_clone`的symbol，仍然会产生相应的hook point
> - libbpf.c与bpf_load.c不同，它使用`perf_event_open()`获取pfd的同时生成hook point。因此它无法使用`sys_clone` symbol生成hook point

使用bpf_load.c写成的代码在[这里](https://github.com/time-river/Linux-eBPF-Learning/blob/main/1-hello/hello_user.c)。

## eBPF Program Internal

eBPF程序并不关心如何执行到它这里的，这些是kprobe、tracepoint、uprobe等做的事情，至于能不能执行、怎么执行用户所写的eBPF代码则是eBPF所关心的。

如同互联网中多数文章所说，eBPF是解释执行的、运行在沙盒中的程序。eBPF程序有着严格的限制，目前发现的：

- 它的状态必须是能确定的，像状态机一样从一个状态转换成另一个状态
- 它不具备读写任意内存空间的能力，大部分内存的读取需使用`bpf_probe_read_{kernel,user}()`函数，只允许具有bpf helper的允许的地方使用bpf helper func改写内存
- 它无法使用`malloc()`分配内存，准确地说它没有标准库，无法使用除了`linux/bpf.h`[[5]]中定义的所有函数（除了`memset() / memcpy() / memmove() / memcmp()`，他们可由编译器提供，即`__builtin_{memset, memcpy, memmove, memcmp}()`[[6]]）
- 对于loop，v5.3及之后也只是允许有限循环状态的loop[[7]][[8]]
- 它不支持BPF-to-BPF call，v5.10及之后也只是在使用libbpf的情况下允许BPF-to-BPF call（这些call是在ELF解析时候完成的）

eBPF在载入程序时会进行模拟执行、检查，入口在`bpf_check()`[[9]]。对于内存访问，会使用`check_mem_access()`[[10]]进行检查。eBPF支持的各类hook方法都实现了`struct bpf_verifier_ops`，其成员`is_valid_access`是函数指针，规定了各类hook方法直接允许访问的内存范围，超出该范围的必须使用`bpf_probe_read_{kernel,user}()`进行访问。Linux对不同特权等级下程序能够访问的内存空间进行了区分，在v5.5之前，`bpf_probe_read()`只能访问内核空间的内存，因此引入了`bpf_probe_read_user()`，`bpf_probe_read()`被重命名为`bpf_probe_read_kernel()`，为了保持兼容`bpf_probe_read()`作为`bpf_probe_read_kernel()`的别名存在。

那么，载入kernel的eBPF程序是如何执行、以及进行BPF helper func调用的呢？

eBPF解释执行的相关代码在`___bpf_prog_run()`[[11]]中。`struct bpf_insn`[[12]]是其指令格式，可以看到，它是定长的指令格式，具体含义在`Documentation/networking/filter.rst`[[13]]中进行了说明。若反汇编eBPF程序会发现，eBPF汇编中是存在`call`指令的，并且在解释器中会发现相关的跳转实现[[14]]，只不过`6`这个值与`bpf_trace_printk()`对不上，而且这看起来怪怪的。回到`bpf_check()`会发现它调用了`fixup_bpf_calls()`[[15]]，这里有一些switch case，通过跳转不同的`BPF_FUNC_xxx`得到不同的与`__bpf_call_base`有关的offset，offset赋给了`insn->imm`，也就有了那种看起来怪怪的调用方法。在`include/uapi/linux/bpf.h`[[16]]中存在着当前版本下所有的BPF_FUNC定义，6即`FN(trace_printk)`，macro展开是`BPF_FUNC_trace_printk`。可这里并没有与`trace_printk`有关的字眼。

```markdown
$ llvm-objdump -d hello_kern.o | grep call
8:       85 00 00 00 06 00 00 00 call 6

/* kernel/bpf/core.c */
static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn, u64 *stack)
	/* CALL */
	JMP_CALL:
		/* Function call scratches BPF_R1-BPF_R5 registers,
		 * preserves BPF_R6-BPF_R9, and stores return value
		 * into BPF_R0.
		 */
		BPF_R0 = (__bpf_call_base + insn->imm)(BPF_R1, BPF_R2, BPF_R3,
						       BPF_R4, BPF_R5);
		CONT;

/* kernel/bpf/verifier.c */
static int fixup_bpf_calls(struct bpf_verifier_env *env)
			switch (insn->imm) {
			case BPF_FUNC_map_lookup_elem:
				insn->imm = BPF_CAST_CALL(ops->map_lookup_elem) -
					    __bpf_call_base;
...
patch_call_imm:
		fn = env->ops->get_func_proto(insn->imm, env->prog);
		/* all functions that have prototype and verifier allowed
		 * programs to call them, must be real in-kernel functions
		 */
```

实际上，在`struct bpf_verifier_ops`另一个成员`get_func_proto`的实现中规定了各类hook方法中能够使用的BPF_FUNC，通用的BPF_FUNC才在`fixup_bpf_calls()`中写明，其余则通过回调`env->ops->get_func_proto()`获取。

因为eBPF的call指令用于调用kernel中定义的各种BPF helper func，这也解释了为啥不支持BPF-to-BPF call。

[1]: https://github.com/torvalds/linux/blob/v5.10/kernel/bpf/syscall.c#L2129
[2]: https://lwn.net/Articles/800606/
[3]: https://confused.ai/posts/rust-bpf-target
[4]: https://github.com/libbpf/libbpf
[5]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
[6]: https://docs.cilium.io/en/latest/bpf/
[7]: https://lwn.net/Articles/773605/
[8]: https://lwn.net/Articles/794934/
[9]: https://github.com/torvalds/linux/blob/v5.10/kernel/bpf/verifier.c#L11815
[10]: https://github.com/torvalds/linux/blob/v5.10/kernel/bpf/verifier.c#L3401
[11]: https://github.com/torvalds/linux/blob/v5.10/kernel/bpf/core.c#L1372
[12]: https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h#L65
[13]: https://github.com/torvalds/linux/blob/v5.10/Documentation/networking/filter.rst
[14]: https://github.com/torvalds/linux/blob/v5.10/kernel/bpf/core.c#L1521
[15]: https://github.com/torvalds/linux/blob/v5.10/kernel/bpf/verifier.c#L10843
[16]: https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h#L3746
