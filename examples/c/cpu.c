// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "cpu.skel.h"

#define INTERVAL 5
#define MAX_KEY_LENGTH 100
#define MAX_ENTRIES 100

typedef struct KeyValue {
    __u32 key[MAX_KEY_LENGTH];
    __u64 value;
} KeyValue;

typedef struct KeyValueStore {
    KeyValue entries[MAX_ENTRIES];
    int size;
} KeyValueStore;

void init_store(KeyValueStore *store) {
    store->size = 0;
}


int add_entry(KeyValueStore *store, __u32 key, __u64 value) {
    if (store->size >= MAX_ENTRIES) {
        printf("Store is full!\n");
        return -1; // Store is full
    }

    for (int i = 0; i < store->size; i++) {
        if (store->entries[i].key == key) {
            store->entries[i].value = value; // Update value by key
            return 0; // Successfully updated
        }
    }

    // Add new entry
    store->entries[store->size].key = key;
    store->entries[store->size].value = value;
    store->size++;
    return 0; // Successfully added
}

// Поиск значения по ключу
__u64* get_value(KeyValueStore *store, __u32 key) {
    for (int i = 0; i < store->size; i++) {
        if (store->entries[i].key == key) {
            return &store->entries[i].value; // Return pointer to value
        }
    }
    return NULL; // Key not found
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct cpu_bpf *skel;
	int err;

	long num_cores = sysconf(_SC_NPROCESSORS_ONLN);

	if (num_cores == -1) {
        perror("sysconf");
        return 1;
    }

    KeyValueStore store;
    init_store(&store);

    printf("Number of CPU cores: %ld\n", num_cores);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = cpu_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = cpu_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = cpu_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Tracking CPU usage. Press Ctrl+C to stop.\n");

    while (1) {
        __u32 pid = 0, next_pid;
        __u64 value;
        __u64 total_time = 0;
        while (bpf_map_get_next_key(bpf_map__fd(skel->maps.cpu_times), &pid, &next_pid) == 0) {
            if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.cpu_times), &next_pid, &value) == 0) {
                printf("Process %u used %llu ns of CPU time\n", next_pid, value);
                __u64 *process_time = get_value(&store, next_pid);
                if (process_time != NULL) {
                    __u64 delta = value - *process_time;
                    add_entry(&store, next_pid, delta);
                } else {
                    __u64 initial_time = 0;
                    add_entry(&store, next_pid, initial_time);
                }
                total_time += value;
            }
            pid = next_pid;
        }

        for (int i = 0; i < store->size; i++) {
            __u64 percent = (total_time > 0) ? (store.entries[i].value * 100) / total_time : 0;
            printf("Process %u used %llu ns of CPU time, which is %llu%% of total\n", store.entries[i].key, store.entries[i].value, percent);
        }

        sleep(INTERVAL);
    }

cleanup:
	cpu_bpf__destroy(skel);
	return -err;
}