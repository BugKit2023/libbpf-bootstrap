#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "cpu.skel.h"

#define LOG_BUF_SIZE 256

struct log_event {
    int pid;
    char data[LOG_BUF_SIZE];
};

// Функция для обработки событий из perf buffer
static void handle_event(void *ctx, int cpu, void *data, __aligned(8) __size_t size) {
    struct log_event *event = (struct log_event *)data;
    printf("Captured log from PID %d: %s\n", event->pid, event->data);
}

int main(int argc, char **argv) {
    struct logs_bpf *skel;
//    struct logs_map *map;
//    int map_fd;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = logs_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = logs_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

//    map = bpf_object__find_map_by_name(obj, "events");
//    if (!map) {
//        fprintf(stderr, "Failed to find map\n");
//        return 1;
//    }
//
//    map_fd = logs_map__fd(map);

    /* Attach tracepoint handler */
    err = logs_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

//    struct bpf_ring_buffer *rb;
//    rb = bpf_ring_buffer__new(map_fd, handle_event, NULL, NULL);
//    if (!rb) {
//        perror("bpf_ring_buffer__new");
//        return 1;
//    }
//
//    printf("Listening for log events. Press Ctrl+C to stop.\n");
//
//    // Основной цикл обработки событий
//    while (1) {
//        if (bpf_ring_buffer__poll(rb, 100) < 0) {
//            perror("bpf_ring_buffer__poll");
//        }
//    }
//
//    bpf_ring_buffer__free(rb);
    return 0;

cleanup:
    logs_bpf__destroy(skel);
    return -err;
}