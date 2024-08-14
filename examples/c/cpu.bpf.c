// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/bpf_common.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   
    __type(value, u64);
} cpu_times SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/sched_switch")
int on_sched_switch(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns(); 

    u64 *prev_ts = bpf_map_lookup_elem(&cpu_times, &pid);
    if (prev_ts) {
        u64 delta = ts - *prev_ts;
        *prev_ts += delta;
    } else {
        bpf_map_update_elem(&cpu_times, &pid, &ts, BPF_ANY);
    }

    return 0;
}