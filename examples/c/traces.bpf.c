#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_DATA_SIZE 64

struct trace_event_t {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 start_ts;
    __u64 end_ts;
    __u32 status_code;
    char data[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter* ctx) {
    char comm[TASK_COMM_LEN];

    struct trace_event_t event = {};

    void *buf;
    unsigned int buf_size;
    char data[MAX_DATA_SIZE] = {};

    // Получаем имя текущего процесса
    bpf_get_current_comm(&comm, sizeof(comm));

    // Проверяем, что процесс называется "curl"
    if (comm[0] == 'c' && comm[1] == 'u' && comm[2] == 'r' && comm[3] == 'l' && comm[4] == '\0') {
        // Извлекаем указатель на буфер данных и его размер
        buf = (void *)ctx->args[1];
        buf_size = (unsigned int) ctx->args[2];

        if (buf_size < 0) {
            return 0;
        }
        // Ограничиваем размер буфера, чтобы избежать переполнения
        if (buf_size > MAX_DATA_SIZE) {
            buf_size = MAX_DATA_SIZE;
        }

        // Считываем данные из пользовательского пространства
        bpf_probe_read_user(&event.data, buf_size, buf);

        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.tid = bpf_get_current_pid_tgid();
        event.type = 1;
        event.start_ts = bpf_ktime_get_ns();
        //__builtin_memcpy(event.data, data, buf_size);

        // Логируем размер и содержимое данных
        bpf_printk("curl sendto() called: data_len=%d, data=%s\n", buf_size, event.data);
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }

    return 0;
}

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
    event.type = 2;
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

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sendto(struct trace_event_raw_sys_enter* ctx) {
    struct trace_event_t event = {};

    void *buf;
    unsigned int buf_size;
    char data[MAX_DATA_SIZE] = {};

    buf = (void *)ctx->args[1];
    buf_size = (unsigned int) ctx->args[2];
    if (buf_size < 0) {
        return 0;
    }
    // Ограничиваем размер буфера, чтобы избежать переполнения
    if (buf_size > MAX_DATA_SIZE) {
        buf_size = MAX_DATA_SIZE;
    }

    // Считываем данные из пользовательского пространства
    bpf_probe_read_user(&event.data, buf_size, buf);
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.type = 3;
    event.start_ts = bpf_ktime_get_ns();
    // Логируем размер и содержимое данных
    bpf_printk("curl sys_enter_recvfrom() called: data_len=%d, data=%s\n", buf_size, event.data);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));


    return 0;
}

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx) {
    struct trace_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.type = 4;
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