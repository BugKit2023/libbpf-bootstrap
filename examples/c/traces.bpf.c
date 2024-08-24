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

static __always_inline int parse_http_request(struct trace_event_t *event, const char *data, int data_len) {
    if (data_len < 4)
        return 0;

    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') {
        event->http_method = 1;  // GET
    } else if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') {
        event->http_method = 2;  // POST
    } else {
        return 0;  // Not GET or POST
    }

    // Parse URI (assuming it starts after method and a space)
    int i = 4;
    while (i < data_len && data[i] != ' ') {
        event->uri[i-4] = data[i];
        i++;
    }
    event->uri[i-4] = '\0';  // Null-terminate the URI
    return 1;
}

static __always_inline int parse_http_response(struct trace_event_t *event, const char *data, int data_len) {
    if (data_len < 12)
        return 0;

    // Assume status code is in the format "HTTP/1.1 XXX"
    if (data[9] == '2' && data[10] == '0' && data[11] == '0') {
        event->status_code = 200;
    } else if (data[9] == '4' && data[10] == '0' && data[11] == '4') {
        event->status_code = 404;
    } else if (data[9] == '5' && data[10] == '0' && data[11] == '0') {
        event->status_code = 500;
    } else {
        return 0;  // Not a recognized status code
    }

    return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct trace_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.start_ts = bpf_ktime_get_ns();

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct iovec *iov = msg->msg_iov;

    char data[128];
    bpf_probe_read_user(&data, sizeof(data), iov->iov_base);

    if (!parse_http_request(&event, data, iov->iov_len))
        return 0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    event.saddr = inet->inet_saddr;
    event.daddr = inet->inet_daddr;
    event.sport = inet->inet_sport;
    event.dport = inet->inet_dport;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}