// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    u32 fd = (u32)ctx->di;
    u64 count = ctx->dx;
    void *buf = (void *)ctx->si;

    // Вывод информации о системном вызове
    bpf_trace_printk("FD: %d, Bytes: %llu, Data: %s\n", fd, count, (char *)buf);
    return 0;
}