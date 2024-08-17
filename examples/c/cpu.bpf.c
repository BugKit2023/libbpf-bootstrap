// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);  // Process PID
    __type(value, u64); // Last update time in ns
} last_update SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);  // Process PID
    __type(value, u64); // Accumulated CPU time in ns
} cpu_times SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/sched/sched_switch")
int on_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u32 pid_prev = ctx->prev_pid;  // PID процесса, который уходит с CPU
    u32 pid_current = ctx->next_pid;
    u64 ts = bpf_ktime_get_ns();

    if (pid_current != 0) {
        bpf_map_update_elem(&last_update, &pid_current, &ts, BPF_ANY);
    }

    if (pid_prev != 0) {
    u64 *prev_ts = bpf_map_lookup_elem(&last_update, &pid_prev);
        if (prev_ts) {
            u64 delta = ts - *prev_ts;
            u64 *cpu_time = bpf_map_lookup_elem(&cpu_times, &pid_prev);
            if (cpu_time) {
                *cpu_time += delta;
            } else {
                u64 initial_time = delta;
                bpf_map_update_elem(&cpu_times, &pid_prev, &initial_time, BPF_ANY);
            }
        } else {
            u64 initial_time = 0;
            bpf_map_update_elem(&cpu_times, &pid_prev, &initial_time, BPF_ANY);
        }
    }

    return 0;
}