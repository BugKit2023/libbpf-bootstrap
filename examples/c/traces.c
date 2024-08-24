#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "traces.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size) {
	struct {
        __u32 pid;
        __u32 tid;
        __u32 saddr;
        __u32 daddr;
        __u16 sport;
        __u16 dport;
        __u64 start_ts;
        __u64 end_ts;
        __u32 http_method;
        __u32 status_code;
        char uri[128];
	} *e = data;

	char saddr_str[INET_ADDRSTRLEN];
    char daddr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->saddr, saddr_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &e->daddr, daddr_str, INET_ADDRSTRLEN);

    printf("PID: %u\n", e->pid);
    printf("TID: %u\n", e->tid);
    printf("Source IP: %s\n", saddr_str);
    printf("Destination IP: %s\n", daddr_str);
    printf("Source Port: %u\n", ntohs(e->sport));
    printf("Destination Port: %u\n", ntohs(e->dport));
    printf("Start Timestamp: %llu\n", e->start_ts);
    printf("End Timestamp: %llu\n", e->end_ts);
    printf("HTTP Method: %u\n", e->http_method);
    printf("Status Code: %u\n", e->status_code);
    printf("URI: %s\n", e->uri);
}

int main(int argc, char **argv)
{
	struct traces_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = traces_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */

	/* Load & verify BPF programs */
	err = traces_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	perf_fd = traces_map__fd(skel->maps.events);
    if (perf_fd < 0) {
        fprintf(stderr, "Failed to get perf event map FD\n");
        goto cleanup;
    }

	/* Attach tracepoint handler */
	err = traces_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

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

cleanup:
	traces_bpf__destroy(skel);
	return -err;
}
