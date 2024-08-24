// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct trace_event_t {
    __u32 pid;
    __u32 tid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 start_ts;
    __u64 end_ts;
    __u32 http_method;
    __u32 status_code;
    char uri[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct trace_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.start_ts = bpf_ktime_get_ns();

    // Extract addresses and ports
    struct inet_sock *inet = (struct inet_sock *)sk;
    event.saddr = inet->inet_saddr;
    event.daddr = inet->inet_daddr;
    event.sport = inet->inet_sport;
    event.dport = inet->inet_dport;

    // For simplicity, assume this is an HTTP request with method "GET"
    // and a dummy URI "/example".
    event.http_method = 1;  // Example: 1 could represent GET
    __builtin_memcpy(event.uri, "/example", sizeof("/example"));

    // Submit the event to the userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}