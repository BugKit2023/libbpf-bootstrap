#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "logs.skel.h"

struct Event {
    uint64_t timestamp;
    int fd;
    int pid;
};

void process_event(void *data, size_t size) {
    // Предполагаем, что структура Event соответствует размеру данных
    struct Event *event = (struct Event *)data;

    printf("Timestamp: %llu\n", event->timestamp);
    printf("File Descriptor: %d\n", event->fd);
    printf("PID: %d\n", event->pid);
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    struct logs_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    struct perf_event_attr pe = {
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .size = sizeof(pe),
        .disabled = 1,
        .exclude_kernel = 1,
        .exclude_hv = 1,
    }

    int perf_fd = perf_event_open(&pe, -1, -1, -1, 0);
    if (perf_fd < 0) {
        perror("perf_event_open failed");
        return 1;
    }

    /* Open BPF application */
    skel = logs_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = logs_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = logs_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Tracking Logs usage. Press Ctrl+C to stop.\n");

    char buf[4096];
    while (1) {
        ssize_t bytes = read(perf_fd, buf, sizeof(buf));
        printf("Hello")
        sleep(5);
    }

    close(perf_fd);

cleanup:
    logs_bpf__destroy(skel);
    return -err;
}