// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_LOG_SIZE 256

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(void *ctx) {
    // Входные параметры для tracepoint
    int fd = (int)BPF_CORE_READ(ctx, fd);
    const char *buf = (const char *)BPF_CORE_READ(ctx, buf);
    size_t count = (size_t)BPF_CORE_READ(ctx, count);

    char data[MAX_LOG_SIZE];
    int pid = bpf_get_current_pid_tgid() >> 32; // Получаем PID процесса

    // Проверяем, что запись идет в stdout (fd == 1) или stderr (fd == 2)
    if (fd != 1 && fd != 2) {
        return 0;
    }

    // Копируем данные из пользовательского буфера в eBPF
    if (bpf_probe_read_user(&data, sizeof(data), buf) == 0) {
        // Отправляем данные и PID в perf buffer
        struct {
            int pid;
            char data[MAX_LOG_SIZE];
        } event = {pid};
        __builtin_memcpy(event.data, data, count > MAX_LOG_SIZE ? MAX_LOG_SIZE : count);
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }

    return 0;
}