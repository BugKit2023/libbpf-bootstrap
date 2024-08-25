#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_BUF_SIZE 64

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
    char uri[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct trace_event_t event = {};
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (comm[0] != 'c' || comm[1] != 'u' || comm[2] != 'r' || comm[3] != 'l' || comm[4] != '\0') {
        return 0;
    }

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.start_ts = bpf_ktime_get_ns();

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    // Чтение адресов и портов
    event.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}