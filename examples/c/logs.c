#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <sys/poll.h>
#include "logs.skel.h"

#define BUF_SIZE 4096
#define POLL_TIMEOUT 5000

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    struct logs_bpf *skel;
    int err;
    int perf_fd;
    struct pollfd pfd;
    char buf[BUF_SIZE];

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

    /* Attach tracepoint handler */
    err = logs_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    perf_fd = bpf_map__fd(skel->maps.events);
    if (perf_fd < 0) {
        fprintf(stderr, "Failed to get perf event map FD\n");
        goto cleanup;
    }

    printf("Tracking Logs usage. Press Ctrl+C to stop.\n");
    printf("Attempting to read from perf_fd: %d\n", perf_fd);

    pfd.fd = perf_fd;
    pfd.events = POLLIN;  // Мониторинг на доступность данных для чтения

    while (1) {
        // Ожидаем, пока появятся данные
        int ret = poll(&pfd, 1, POLL_TIMEOUT); // Тайм-аут 5000 миллисекунд

        if (ret < 0) {
            perror("poll failed");
            break;
        } else if (ret == 0) {
            printf("Timeout, no data available\n");
            continue;
        }

        // Если есть доступные данные для чтения
        if (pfd.revents & POLLIN) {
            ssize_t bytes = read(perf_fd, buf, sizeof(buf));
            if (bytes < 0) {
                perror("read failed");
                break;
            } else if (bytes == 0) {
                printf("No data read\n");
            } else {
                // Обработка данных из `buf`
                printf("Data received: %zd bytes\n", bytes);
                // Можно добавить обработку данных из `buf` здесь
            }
        }

        // Дополнительный вывод для отладки
        printf("HELLO!\n");
        sleep(5);
    }

    close(perf_fd);

cleanup:
    logs_bpf__destroy(skel);
    return -err;
}