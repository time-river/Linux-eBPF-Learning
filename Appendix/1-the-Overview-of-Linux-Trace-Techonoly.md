# the Overview of Linux Tracing Techonoly

Blog Post: [Linux动态追踪技术一览](https://vvl.me/2020/12/the-Overview-of-Linux-Tracing-Tools/)

## Introduction

Linux存在众多tracing tools，比如ftrace、perf，他们可用于内核的调试、提高内核的可观测性。众多的工具也意味着繁杂的概念，诸如tracepoint、trace events、kprobe、eBPF等让人头大，让人搞不清楚他们到底是干什么的。本文尝试理清这些概念。

## Noun Explanation

[Linux tracing systems & how they fit together][2]一文将这一系列概念划分为三类：

1. 数据采集方法（Data Sources）
2. 数据的加工与传递手段（Mechanisms for Collection your Delicious Data）
3. 用户前端工具（User Frontends）

借用这三类名词，我将这一系列概念的划分稍微与上文中不同。

### Data Sources

Keywords: **kprobe**, **uprobe**, **tracepoint**, **USDT**, **perf event**

probe代指一类行为：它能够在程序运行时动态地修改指令，从而实现tracing的机制。它分为用于kernel的kprobe、用于application的uprobe两类。他们都利用了CPU提供的单步调试指令（x86即`int 3`，1字节的`0xcc`指令）来实现，kprobe / uprobe可用于hook函数体的任意位置，kretprobe / uretprobe则专门用来hook函数的返回地址。

tracepoint为编译器在编译时插入代码段的一条指令，程序在运行时能够利用这条指令实现跳转。它分为用于kernel的tracepoint、用于application的USDT（Userland Statically Defined Tracing）。这里的dynamic意味着该tracepoint是编译器在编译时自动向函数的起始处添加的指令GCC允许在编译程序时添加参数`-pg`令编译出来的程序在每一个函数起始处自动插入5字节的`call mcount`指令（AMD64为`push rbp`之后），从而实现函数的入口与返回时的hook。而static，即在代码中静态定义的函数调用它是相对dynamic来讲的，在不保证API稳定的情况下，这么做的好处便显而易见了（不会因API的变更而失效）。

tracepoint用于kernel中，分为static tracepoint与dynamic tracepoint。用于application的tracepoint被称为USDT，因为USTD（`nop`指令）由编译器静态添加至ELF二进制中，对于解释型语言，比如Node.js、Python，则无法使用，因此出现了dynamic USTDdynamic USTD预编译了一套具有特定USDT的shared library，该library可由隐藏了细节的目标语言API调用，从而实现dynamic probe。

> Note:
>
> 1. 若开启该CPU架构的GCC支持`-mfentry`选项，则Kconfig选项`CONFIG_HAVE_FENTRY`打开，GCC在编译时会在函数起始处插入5字节的`call __fentry__`（AMD64为`push rbp`之前）而不是`call mcount`
> 2. 在Kconfig选项`CONFIG_OPTPROBES`打开后，使用kprobe hook函数起始地址，kprobe会使用`call __fentry__`替代插入单步调试指令
> 3. tracepoint通常默认为kernel内部的static tracepoint，比如用于tracing syscall的syscall tracepoint（commit [a871bd33a][4]）；名词ftrace，使用的tracepoint通常指dynamic tracepoint

此外，还有基于硬件performance monitoring counter（PMC）实现的数据获取方式。

### Mechanisms for Collection your Delicious Data

Keywords: **ftrace**, **tracer**, **trace events**, **tracepoint-based events**, **kprobe-based events**, **uprobe-based events**, **perf events**, **eBPF**

ftrace，更精确地称呼为function tracer，能够用来追踪函数的调用情况。在历史上function tracer由ftrace重命名而来，而ftrace发展发展成为一种能够支持多类tracing utilities的框架，它基于dynamic tracepoint，由ftrace ring buffer、`tracefs`构成该框架的核心。在ftrace框架下实现的各类tracer，具体实现了tracing的行为，用于探测kernel中发生了什么，他们使用`trace_print()`将探测得到的数据写入ftrace ring buffer中，用户则可以通过读取tracefs中的`trace`或`trace_pipe`得到相关的数据。

狭义上的tracer指的是tracefs中文件`available_tracers`所显示的那些，比如可绘制出函数调用关系的[function graph tracer][5]；广义上的tracer，包含了各类加工数据的方法，比如trace events，eBPF tracer。

trace events是kernel中预定义的、用于传递tracing到的数据的一种行为，利用了tracefs向用户传递数据。有使用了static tracepoint的tracepoint-based events、使用了kprobe的kprobe-based events、使用了uprobe的uprobe-based events三类，后两种合称为dynamic events。

不同于trace events，使用perf events（performance events）采集到的数据能够用来衡量性能，它最初名为performance counter，使用的是PMU获取数据，后来它能够利用的数据获取方式不再局限为PMU，亦发展称为一种框架，实现了类似trace ring buffer的perf ring buffer，perf ring buffer种的数据能够通过`perf_event_open()`系统调用传递给用户。当前它包括使用硬件PMC实现的hardware events、基于kernel counter实现的software events、使用了tracepoint的tracepoint events。

kprobe提供了`register_kprobe()`系列API，允许用户编写kernel modules、注册hook点的pre-handler与post-handler回调函数用以处理捕获到的数据。uprobe虽然也有类似kprobe的`register_uprobe_event()`API，但它不对用户暴露。

eBPF（extended BPF）最初由过滤网络数据包的BPF发展而来，它是kernel内部的虚拟机，eBPF程序能够对tracepoint、kprobe、uprobe、USDT探测得到数据进行处理，使用tracefs、`perf_event_open()，或eBPF maps将数据传递给用户。eBPF maps是一种用于运行在kernel中的eBPF程序存储数据的方法，使用它还能够令eBPF程序与userspace中的application之间共享数据。

#### Bridge Kernelspace and Userspace

tracing有三类用于kernelspace、userspace之间通信的方法：

- `tracefs`：使用ftrace ring buffer存储数据，通过读取文件`trace` / `trace_pipe`取得数据
- `perf_event_open()`: 使用perf ring buffer存储数据，通过系统调用`perf_event_open()`取得数据
- `eBPF maps`: eBPF程序采用的数据存储方式，使用`bpf_map_lookup_elem()` / `bpf_map_update_elem()` / `bpf_map_delete_elem()` API令eBPF program与application进行双向通信

### User Frontends

Keywords: **systemtap (stap)**, **trace-cmd**, **perf**, **LLTng**, **Dtrace**, **bcc**, **bpftrace**

为了便于使用，在上述数据采集方法与加工方式的基础上，衍生出一系列易于用户使用的前端工具（悄悄地说：我也没搞明白他们的技术原理，所以放图好了）：

![Instrumentation Methods for Online Analytics](/pics/Instrumentation-Methods-for-Online-Analytics.png)

Note: 图来自[LinucConJapan2015: Dynamic Probes for LinuxRecent updates][7]，Interface一栏缺少了eBPF maps

## 总结

- kprobe、uprobe能够hook函数代码中的任意位置，一个用于kernel，一个用于application
- tracepoint是埋在代码中的静态hook点
- ftrace是框架，使用dynamic tracepoint，利用tracer处理数据，使用tracefs输出数据
- 广义上的tracer是数据加工的方式
- trace events是一种输出捕获得到的数据的模板，使用tracefs输出数据，根据数据的获取方式分为tracepoint-based events、kprobe-based events、uprobe-based events三类
- perf events采集到的数据用于衡量性能，亦发展称为一种框架
- USDT是用来trace ELF binary application的，用来trace解释型语言的是dynamic USDT

## Reference

1. [lwn.net: Unifying kernel tracing][1]
2. [Julia Evans Blog: Linux tracing systems & how they fit together][2]
3. [Slides: Unified Tracing Platform Bringing tracing together][3]
4. [Linux wiki: Linux kernel profling with perf][6]
5. [LinucConJapan2015: Dynamic Probes for LinuxRecent updates][7]

[1]: https://lwn.net/Articles/803347/
[2]: https://jvns.ca/blog/2017/07/05/linux-tracing-systems/
[3]: https://static.sched.com/hosted_files/osseu19/5f/unified-tracing-platform-oss-eu-2019.pdf
[4]: https://github.com/torvalds/linux/commit/a871bd33a6c0bc86fb47cd02ea2650dd43d3d95f
[5]: https://github.com/torvalds/linux/blob/v5.9/kernel/trace/trace_functions_graph.c#L1281
[6]: https://perf.wiki.kernel.org/index.php/Tutorial
[7]: https://events.static.linuxfound.org/sites/events/files/slides/LinuxConJapan2015-DynamicProbes.pdf
