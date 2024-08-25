#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_BUF_SIZE 64

struct trace_event_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
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

    // Log entry point
    bpf_printk("Entering socket_handler\n");

    // Load Ethernet protocol
    bpf_skb_load_bytes(skb, 12, &proto, sizeof(proto));
    proto = bpf_ntohs(proto);
    bpf_printk("Protocol: 0x%x\n", proto);
    if (proto != 0x0800) // ETH_P_IP
        return 0;

    // Load IP header length
    bpf_skb_load_bytes(skb, nhoff, &hdr_len, sizeof(hdr_len));
    hdr_len = (hdr_len & 0x0F) * 4;

    // Load protocol type
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, sizeof(ip_proto));
    bpf_printk("IP Protocol: %d\n", ip_proto);
    if (ip_proto != IPPROTO_TCP)
        return 0;

    // Calculate TCP header length
    tcp_hdr_len = nhoff + hdr_len;
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));
    tlen = bpf_ntohs(tlen);
    bpf_printk("Total length: %d\n", tlen);

    __u8 doff;
    bpf_skb_load_bytes(skb, tcp_hdr_len + 12, &doff, sizeof(doff)); // Offset to data
    doff = (doff & 0xF0) >> 4;
    doff *= 4;

    payload_offset = nhoff + hdr_len + doff;
    payload_length = tlen - hdr_len - doff;

    bpf_printk("Payload offset: %d, Payload length: %d\n", payload_offset, payload_length);

    if (payload_length < 7)
        return 0;

    bpf_skb_load_bytes(skb, payload_offset, line_buffer, sizeof(line_buffer));
    bpf_printk("First few bytes of payload: %s\n", line_buffer);

    if (line_buffer[0] == 'G' && line_buffer[1] == 'E' && line_buffer[2] == 'T') {
        bpf_skb_load_bytes(skb, payload_offset + 4, event.uri, MAX_BUF_SIZE);
    } else if (line_buffer[0] == 'P' && line_buffer[1] == 'O' && line_buffer[2] == 'S' && line_buffer[3] == 'T') {
        bpf_skb_load_bytes(skb, payload_offset + 5, event.uri, MAX_BUF_SIZE);
    } else {
        return 0;
    }

    bpf_printk("Captured URI: %s\n", event.uri);

    // Load IP addresses and ports
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &event.saddr, sizeof(event.saddr));
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &event.daddr, sizeof(event.daddr));
    bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct tcphdr, source), &event.sport, sizeof(event.sport));
    bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct tcphdr, dest), &event.dport, sizeof(event.dport));

    bpf_printk("Source IP: %x, Destination IP: %x\n", event.saddr, event.daddr);
    bpf_printk("Source Port: %d, Destination Port: %d\n", event.sport, event.dport);

    // Submit event
    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
