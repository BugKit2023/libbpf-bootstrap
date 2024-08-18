// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define STDOUT_FD 1
#define ECHO_CMD "echo"
#define BUF_SIZE 256

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
    int pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("HELlllO %d\n", sizeof("HELlllO %d\n"), pid);

    int fd = BPF_CORE_READ(ctx, args[0]);
    const char *buf = (const char *)BPF_CORE_READ(ctx, args[1]);
    size_t count = BPF_CORE_READ(ctx, args[2]);

    if (fd == STDOUT_FD) {
    }
//
//    if (fd == STDOUT_FD) {
//        char temp_buf[BUF_SIZE];
//
//        if (count <= sizeof(temp_buf)) {
//
//
//            if (bpf_probe_read_kernel(temp_buf, count, buf) == 0) {
//                if (bpf_strstr(temp_buf, ECHO_CMD) != NULL) {
//                    int pid = bpf_get_current_pid_tgid() >> 32;
//
//                    bpf_trace_printk("HELlllO %d\n", sizeof("HELlllO %d\n"), pid);
//                }
//            }
//
//        }
//    }

    return 0;
}