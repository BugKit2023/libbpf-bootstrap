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
    char uri[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline int parse_http_request(struct trace_event_t *event, const char *data, int data_len) {
    bpf_printk("Parsing HTTP request, data length: %d\n", data_len);
    bpf_printk("Data content: %.20s\n", data);

    if (data_len < 4)
        return 0;

    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') {
        event->http_method = 1;  // GET
        bpf_printk("GET request detected\n");
    } else if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') {
        event->http_method = 2;  // POST
        bpf_printk("POST request detected\n");
    } else {
        bpf_printk("Unknown method or not HTTP request\n");
        return 0;  // Not GET or POST
    }

    int i = 4;
    int uri_index = 0;
    while (i < data_len && data[i] != ' ' && uri_index < sizeof(event->uri) - 1) {
        event->uri[uri_index++] = data[i++];
    }
    event->uri[uri_index] = '\0';

    bpf_printk("Parsed URI: %s\n", event->uri);

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
    char comm[16];

    bpf_get_current_comm(&comm, sizeof(comm));

    if (comm[0] != 'c' || comm[1] != 'u' || comm[2] != 'r' || comm[3] != 'l' || comm[4] != '\0') {
        return 0;
    }

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.start_ts = bpf_ktime_get_ns();

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct iovec iov;

    int res = bpf_probe_read_kernel(&iov, sizeof(iov), &msg->msg_iter.iov);
    bpf_printk("tcp_sendmsg: Kelner data, ret=%d\n", res);

    if (iov.iov_base == NULL || iov.iov_len == 0) {
        bpf_printk("tcp_sendmsg: iov is invalid\n");
        return 0;
    }

    char data[64];  // Увеличили буфер
    int ret = bpf_probe_read_user(&data, sizeof(data) - 1, iov.iov_base);
    bpf_printk("tcp_sendmsg: User data, ret=%d\n", ret);

    bpf_printk("tcp_sendmsg: Data content %.20s\n", data);


    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') {
        event.http_method = 1;  // GET
        __builtin_memcpy(event.uri, data + 4, sizeof(event.uri));
    } else if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') {
        event.http_method = 2;  // POST
        __builtin_memcpy(event.uri, data + 5, sizeof(event.uri));
    }

    event.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    bpf_printk("tcp_sendmsg: Send message\n");

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}


SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
    struct trace_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.end_ts = bpf_ktime_get_ns();

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct iov_iter iter;
    struct iovec iov;

    BPF_CORE_READ_INTO(&iter, msg, msg_iter);
    BPF_CORE_READ_INTO(&iov, &iter, iov);

    char data[128];
    bpf_probe_read_user(&data, sizeof(data), iov.iov_base);

    if (!parse_http_response(&event, data, iov.iov_len))
        return 0;

    // Получение IP-адресов и портов
    event.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event.dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // Отправка события в пространство пользователя
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}