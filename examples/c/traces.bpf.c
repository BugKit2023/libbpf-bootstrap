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
    char uri[MAX_BUF_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("socket")
int socket_handler(struct __sk_buff *skb) {
    struct trace_event_t event = {};
    __u32 nhoff = 14;  // Ethernet header length (ETH_HLEN)
    __u16 proto;
    __u8 hdr_len, ip_proto;
    __u32 tcp_hdr_len;
    __u16 tlen;
    __u32 payload_offset, payload_length;
    char line_buffer[7];

    bpf_skb_load_bytes(skb, 12, &proto, sizeof(proto));
    proto = bpf_ntohs(proto);
    if (proto != 0x0800) // ETH_P_IP
        return 0;

    bpf_skb_load_bytes(skb, nhoff, &hdr_len, sizeof(hdr_len));
    hdr_len = (hdr_len & 0x0F) * 4;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, sizeof(ip_proto));
    if (ip_proto != IPPROTO_TCP)
        return 0;

    tcp_hdr_len = nhoff + hdr_len;
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));
    tlen = bpf_ntohs(tlen);

    __u8 doff;
    bpf_skb_load_bytes(skb, tcp_hdr_len + 12, &doff, sizeof(doff)); // Offset to data
    doff = (doff & 0xF0) >> 4;
    doff *= 4;

    payload_offset = nhoff + hdr_len + doff;
    payload_length = tlen - hdr_len - doff;

    if (payload_length < 7)
        return 0;

    bpf_skb_load_bytes(skb, payload_offset, line_buffer, sizeof(line_buffer));

    if (line_buffer[0] == 'G' && line_buffer[1] == 'E' && line_buffer[2] == 'T') {
        event.http_method = 1;
    } else if (line_buffer[0] == 'P' && line_buffer[1] == 'O' && line_buffer[2] == 'S' && line_buffer[3] == 'T') {
        event.http_method = 2;
    } else {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = BPF_CORE_READ(task, pid);
    event.tid = bpf_get_current_pid_tgid();
    event.start_ts = bpf_ktime_get_ns();

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &event.saddr, sizeof(event.saddr));
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &event.daddr, sizeof(event.daddr));
    bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct tcphdr, source), &event.sport, sizeof(event.sport));
    bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct tcphdr, dest), &event.dport, sizeof(event.dport));

    bpf_skb_load_bytes(skb, payload_offset + 4, event.uri, MAX_BUF_SIZE);

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}