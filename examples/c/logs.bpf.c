// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define STDOUT_FD 1
#define ECHO_CMD "echo"
#define BUF_SIZE 256
#define ECHO_CMD_LEN 4

static __always_inline const char *bpf_strstr(const char *haystack, const char *needle) {
    while (*haystack) {
        const char *h = haystack;
        const char *n = needle;

        while (*h && *n && *h == *n) {
            h++;
            n++;
        }

        if (!*n)
            return haystack;

        haystack++;
    }

    return NULL;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    int fd = BPF_CORE_READ(ctx, args[0]);
    const char *buf = (const char *)BPF_CORE_READ(ctx, args[1]);
    size_t count = BPF_CORE_READ(ctx, args[2]);

    if (fd == STDOUT_FD) {
        // Временный буфер для чтения данных
        char temp_buf[BUF_SIZE];  // Можно изменить размер в зависимости от предполагаемого размера буфера

        if (count <= sizeof(temp_buf)) {
            bpf_probe_read(temp_buf, count, buf);

            // Проверка, содержит ли буфер команду "echo"
            if (bpf_strstr(temp_buf, ECHO_CMD) != NULL) {
                int pid = bpf_get_current_pid_tgid() >> 32;

                // Вывод содержимого буфера, если оно принадлежит команде echo
                bpf_trace_printk("ECHO COMMAND %d: %s\n", pid, temp_buf);
            }
        }
    }

    return 0;
}