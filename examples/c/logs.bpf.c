// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define STDOUT_FD 1

struct Event {
    u64 timestamp;
    int fd;
    int pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    int fd = BPF_CORE_READ(ctx, args[0]);

    if (fd == STDOUT_FD && (pid == 1622 || pid == 1564)) {
        struct Event event = {};
        event.timestamp = bpf_ktime_get_ns();
        event.pid = pid;
        event.fd = fd;

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        bpf_trace_printk("Write syscall detected on stdout by PID %d\n", sizeof("Write syscall detected on stdout by PID %d\n"), pid);
    }
    return 0;
}