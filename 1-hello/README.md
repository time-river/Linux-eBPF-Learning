# Hello eBPF

## Startup: Hello eBPF!

> the output of eBPF program

use arch dependent `sys_clone()`

hello_{user,kern}.c

## Next: Print Syscall `openat()` Parameters

### Kprobe 1

why use `bpf_kprobe_read()`

why can print filename directly?

Notice: using builtin_preserve_access_index() without -g

### Kprobe 2

use bpf_probe_read_{kernel,user}

### Tracepoint

tracepoint-based // not use bpf_probe_read

## Next use eBPF maps

### Version 1

use legancy bpf maps // why use __builtin_memcpy?

### Version 1.0

use btf-typed bpf maps // Notice: __x64_sys_clone instead of sys_clone

new format # why new format?

