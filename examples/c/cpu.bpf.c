// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} cpu_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} last_update SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/sched/sched_switch")
int on_sched_switch(struct pt_regs *ctx) {
    u32 pid_prev = ctx->prev_pid;
    u32 pid_next = ctx->next_pid;
    u64 ts = bpf_ktime_get_ns();

    // Update CPU time for the previous task
    if (pid_prev != 0) {  // Ignore idle task
        u64 *prev_ts = bpf_map_lookup_elem(&last_update, &pid_prev);
        u64 *prev_time = bpf_map_lookup_elem(&cpu_times, &pid_prev);

        if (prev_ts && prev_time) {
            u64 delta = ts - *prev_ts;
            *prev_time += delta;
            bpf_map_update_elem(&cpu_times, &pid_prev, prev_time, BPF_ANY);
        }
        bpf_map_update_elem(&last_update, &pid_prev, &ts, BPF_ANY);
    }

    // Initialize or update the next task's start time
    if (pid_next != 0) {  // Ignore idle task
        bpf_map_update_elem(&last_update, &pid_next, &ts, BPF_ANY);
        u64 initial_cpu_time = 0;
        bpf_map_update_elem(&cpu_times, &pid_next, &initial_cpu_time, BPF_NOEXIST);
    }

    return 0;
}