// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(void *ctx) {
//    u32 fd = (u32)BPF_CORE_READ(ctx, di);  // Использование bpf_core_read для совместимости
//    u64 count = BPF_CORE_READ(ctx, dx);    // Использование bpf_core_read
    // void *buf = (void *)BPF_CORE_READ(ctx, si); // Оставляем это, если действительно нужно

//    bpf_trace_printk("FD: %d, Bytes: %llu\n", fd, count);
    bpf_trace_printk("HELLO\n", sizeof("HELLO\n"));

    return 0;
}