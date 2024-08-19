// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define STDOUT_FD 1
#define ECHO_CMD "echo"
#define BUF_SIZE 128
#define STRING_SIZE 256
#define MAX_LOGS 10

struct Log {
    u64 timestamp;
    char str[STRING_SIZE];
};

struct LogArray {
    struct Log logs[MAX_LOGS];
    int count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct LogArray);
} logs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);  // Одно значение на процессор
    __type(key, u32);
    __type(value, struct LogArray);
} temp_logs SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    int fd = BPF_CORE_READ(ctx, args[0]);
    const char *buf = (const char *)BPF_CORE_READ(ctx, args[1]);
    size_t count = BPF_CORE_READ(ctx, args[2]);

    if (fd != STDOUT_FD || count == 0) {
        return 0;
    }

    struct LogArray *log_array;
    log_array = bpf_map_lookup_elem(&logs, &pid);
    if (!log_array) {
        // Если запись для данного PID еще не существует, создаем новую
        struct LogArray new_log_array = {};
        new_log_array.count = 0;

        bpf_map_update_elem(&logs, &pid, &new_log_array, BPF_ANY);
        log_array = bpf_map_lookup_elem(&logs, &pid);
        if (!log_array) {
            return 0;  // Если не удалось создать, выходим
        }
    }

    if (log_array->count >= MAX_LOGS) {
        return 0;  // Если массив логов заполнен, не добавляем новые записи
    }

    struct Log *new_log = &log_array->logs[log_array->count];
    new_log->timestamp = bpf_ktime_get_ns();

    if (count < sizeof(new_log->str)) {
//        if (bpf_probe_read_user(new_log->str, count, buf) == 0) {
//            new_log->str[count] = '\0';  // Нулевой символ в конце строки
//        }
    } else {
//        bpf_probe_read_user(new_log->str, sizeof(new_log->str) - 1, buf);
//        new_log->str[sizeof(new_log->str) - 1] = '\0';
    }


//    if (*logs) {
//
//    } else {
//    }

    log_array->count++;

    return 0;
}