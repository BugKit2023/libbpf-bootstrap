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
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();

    u64 *last_ts = bpf_map_lookup_elem(&last_update, &pid);
    u64 *prev_cpu_time = bpf_map_lookup_elem(&cpu_times, &pid);

    if (last_ts && prev_cpu_time) {
        u64 delta = ts - *last_ts;
        u64 updated_time = *prev_cpu_time + delta;

        // Update the CPU time for the process
        bpf_map_update_elem(&cpu_times, &pid, &updated_time, BPF_ANY);
        // Update the last timestamp for the process
        bpf_map_update_elem(&last_update, &pid, &ts, BPF_ANY);
    } else {
        // If no previous data, initialize
        u64 initial_cpu_time = 0;
        bpf_map_update_elem(&cpu_times, &pid, &initial_cpu_time, BPF_ANY);
        bpf_map_update_elem(&last_update, &pid, &ts, BPF_ANY);
    }

    return 0;
}