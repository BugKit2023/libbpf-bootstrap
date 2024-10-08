#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stdarg.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <sys/poll.h>
#include "logs.skel.h"

#define BUF_SIZE 4096
#define POLL_TIMEOUT 5000

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size) {
	struct {
		__u64 timestamp;
		int fd;
        int pid;
        char data[512];
	} *e = data;

	printf("Received event: PID = %d, FD = %d, Timestamp = %llu, message %s\n", e->pid, e->fd, e->timestamp, e->data);
}

int main(int argc, char **argv) {
    struct logs_bpf *skel;
    int err;
    int perf_fd, ret = 0;
    struct perf_buffer *pb;

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
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    perf_fd = bpf_map__fd(skel->maps.events);
    if (perf_fd < 0) {
        fprintf(stderr, "Failed to get perf event map FD\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = logs_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    pb = perf_buffer__new(perf_fd, 8, print_bpf_output, NULL, NULL, NULL);
    ret = libbpf_get_error(pb);
    if (ret) {
    	printf("failed to setup perf_buffer: %d\n", ret);
    	return 1;
    }

    printf("Tracking Logs usage. Press Ctrl+C to stop.\n");
    printf("Attempting to read from perf_fd: %d\n", perf_fd);

    while (1) {
        ret = perf_buffer__poll(pb, 1000);
        if (ret < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", ret);
        } else if (ret == 0) {
            printf("Timeout, no events\n");
        }

        sleep(2);  // Задержка в 2 секунды перед следующим поллингом
    }

    perf_buffer__free(pb);

cleanup:
    close(perf_fd);
    logs_bpf__destroy(skel);
    return -err;
}