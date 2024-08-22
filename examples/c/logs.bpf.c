// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define STDOUT_FD 1
#define MAX_LOG_SIZE 512

struct Event {
    u64 timestamp;
    int fd;
    int pid;
    char data[MAX_LOG_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct Event);
} event_buffer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    int fd = BPF_CORE_READ(ctx, args[0]);

    if (fd == STDOUT_FD && (pid == 104926 || pid == 124693)) {
        u32 key = 0;
        struct Event *event = bpf_map_lookup_elem(&event_buffer, &key);
//        struct Event event = {};
//        event.timestamp = bpf_ktime_get_ns();
//        event.pid = pid;
//        event.fd = fd;
        if (!event) {
            struct Event init_event = {};
            bpf_map_update_elem(&event_buffer, &key, &init_event, BPF_ANY);
            event = bpf_map_lookup_elem(&event_buffer, &key);
            if (!event) {
                return 0;  // Если по какой-то причине всё ещё нет данных, выходим
            }
        }

        event->timestamp = bpf_ktime_get_ns();
        event->pid = pid;
        event->fd = fd;

        const char *buf = (const char *)BPF_CORE_READ(ctx, args[1]);
        unsigned int size = (unsigned int) BPF_CORE_READ(ctx, args[2]);
        bpf_trace_printk("Size %d\n", sizeof("Size %d\n"), size);

        if (size > MAX_LOG_SIZE) {
            size = MAX_LOG_SIZE;
        }

        if (buf && size > 0) {
           bpf_probe_read_user(event->data, size, buf);
        }

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

        bpf_trace_printk("Write syscall detected on stdout by PID %d\n", sizeof("Write syscall detected on stdout by PID %d\n"), pid);
    }
    return 0;
}