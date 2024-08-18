// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(void *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("HELLO %d\n", sizeof("HELLO %d\n"), pid);

    return 0;
}