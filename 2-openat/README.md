---
title: eBPF系列二: 例子openat2
date: 2021-02-12 13:24:10
tags: ["linux", "tracing tools", "eBPF"]
---

Blog Post: [eBPF系列二: 例子openat2](https://vvl.me/2021/02/eBPF-2-example-openat2/)

迫于Linux eBPF文档过少我边学习边把对其的理解记录下来供后来者参考
本文是eBPF系列的第二篇例子openat2
若对Linux tracing技术不清晰可参考前置篇[the Overview of Linux Tracing Tools](/2020/12/the-Overview-of-Linux-Tracing-Tools/)
若对eBPF的工作流程不清晰可参考[eBPF系列一Hello eBPF](/2021/01/eBPF-1-Hello-eBPF/)

## Introduction

在计算机中运行程序读写文件都会涉及到文件的打开操作Linux v5.10与文件打开相关的系统调用有[`open() / creat() / openat() / openat2`](https://man7.org/linux/man-pages/man2/creat.2.html)这四类在使用glibc v2.32时几乎所有的文件打开操作使用的都是`openat2()`这个系统调用

`openat2()`是POSIX标准定义的系统调用之一用于文件的创建或打开它有4个参数其中第一个参数`dirfd`为文件夹的描述符第二个参数`pathname`为文件路径

这里实现一个eBPF程序他能获取系统调用`openat()`的前两个参数信息

## Instance

这些源码在[这里](https://github.com/time-river/Linux-eBPF-Learning/tree/main/2-openat)

### Example 1

在v5.10版本的内核上系统调用入口`SYSCALL_DEFINE4(openat2...)`对参数做了一些简单的检查后调用的是[`do_sys_openat2()`](https://github.com/torvalds/linux/blob/v5.10/fs/open.c#L1223)进行进一步处理其因此可以使用kprobe hook `do_sys_openat2()`间接地打印`openat2()`的参数信息它的第一二个参数含义等同于`openat2()`因此打印前两个参数信息即可相关源码主要如下

```c
SEC("kprobe/do_sys_openat2")
int hello(struct pt_regs *ctx) {
	const int dirfd = PT_REGS_PARM1(ctx);
	const char *pathname = (char *)PT_REGS_PARM2(ctx);
	char fmt[] = "@dirfd='%d' @pathname='%s'";

	bpf_trace_printk(fmt, sizeof(fmt), dirfd, pathname);

	return 0;
}
```

运行

```bash
$ make hello openat1_kern.o
$ sudo ./hello openat1_kern.o
```

### Example 2

参数`pathname`在`do_sys_openat2()`是个指向用户态程序空间的`char`类型的指针若想把文件名复制到eBPF程序中则需要借助`bpf_probe_read_user_str()`了

```c
char msg[256];

bpf_probe_read_user_str(msg, sizeof(msg), pathname);
```

#### Internal

Linux区分了不同特权等级下程序可访问的虚拟内存空间范围它是通过`access_ok()`检查`struct thread_info`中的`addr_limit`来实现的有一组API `{get,set}_fs()`可用于在kernel运行时中控制可访问的内存空间范围

> Note:
> 1. `struct thread_info`是CPU架构专属类型并非每类都有`addr_limit`对x86来讲它是段寄存器`FS`
> 2. `set_fs()`会引起一些security bugs因此当前Linux中在尽力去除这组API[[1]][[2]]

### Example 3

这里写一写怎么直接hook系统调用的入口即`SYSCALL_DEFINE4(openat2...)`

`SYSCALL_DEFINE4`一步步展开如下

```c
SYSCALL_DEFINE4
--> SYSCALL_DEFINEx
--> SYSCALL_METADATA // syscall tracepoint的封装
    __SYSCALL_DEFINEx

// for x86
__SYSCALL_DEFINEx
--> __X64_SYS_STUBx // amd64使用
    __IA32_SYS_STUBx // ia32使用

// for amd64
__X64_SYS_STUBx
--> __SYS_STUBx(x64, sys##name, SC_X86_64_REGS_TO_ARGS(x, __VA_ARGS__)))
--> long __##abi##_##name(const struct pt_regs *regs)
```

拼接起来amd64架构系统调用`openat2()`的入口函数名为`__x64_sys_openat2()`参数类型是`struct pt_regs *`因此eBPF程序这么写

```c
SEC("kprobe/sys_openat")
int hello(struct pt_regs *ctx) {
	char fmt[] = "@dirfd='%d' @pathname='%s'";
	struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	int dirfd = PT_REGS_PARM1_CORE(real_regs);
	char *pathname = (char *)PT_REGS_PARM2_CORE(real_regs);

	bpf_trace_printk(fmt, sizeof(fmt), dirfd, pathname);

	return 0;
}
```

代码中`SEC("kprobe/sys_openat")`表示kprobe的hook point为`sys_openat`实际上用户态程序hello在调用`load_and_attach()`时候会检查kprobe的hook point前缀是否是`sys_`若是对amd64则[自动添加`__x64_`前缀](https://github.com/time-river/Linux-eBPF-Learning/blob/main/2-openat/bpf_load.c#L191)

macro `PT_REGS_PARMx_CORE`对`bpf_probe_read_kernel()`做了封装可以简单地认为用于获取hook func的第x个参数因hook func的参数是`struct pt_regs *`所以需要使用`bpf_probe_read_kernel()`取得`struct pt_regs`进而获取得到系统调用`SYSCALL_DEFINE4(openat2...)`所示的参数信息

### Example 4

Linux内部API经常变更使用kprobe hook特定的函数名不具有普适性Linux为系统调用提供了tracepoint若用tracepoint例子则这么写

```c
struct syscalls_enter_openat_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long syscall_nr;
	long dfd;
	long filename_ptr;
	long flags;
	long mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int hello(struct syscalls_enter_openat_args *ctx) {
	char fmt[] = "@dirfd='%d' @pathname='%s'";

	bpf_trace_printk(fmt, sizeof(fmt), ctx->dfd, (char *)ctx->filename_ptr);

	return 0;
}
```

`struct syscalls_enter_openat_args`成员信息来自tracefs中的文件`events/syscalls/sys_enter_openat2/format`

## Reference

- [LWN.net: A farewell to set_fs()?][1]
- [LWN.net: Saying goodbye to set_fs()][2]

[1]: https://lwn.net/Articles/722267/
[2]: https://lwn.net/Articles/832121/
