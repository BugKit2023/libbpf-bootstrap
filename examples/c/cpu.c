#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "cpu.skel.h"


#define INTERVAL 5
#define MAX_ENTRIES 1024

typedef struct KeyValue {
    __u32 key;    // PID процесса
    __u64 value;  // Время работы за последние 5 секунд
    __u64 last_update; // Время последнего обновления
} KeyValue;

typedef struct KeyValueStore {
    KeyValue entries[MAX_ENTRIES];
    int size;
} KeyValueStore;

void init_store(KeyValueStore *store) {
    store->size = 0;
}

int add_entry(KeyValueStore *store, __u32 key, __u64 value, __u64 last_update) {
    if (store->size >= MAX_ENTRIES) {
        printf("Store is full!\n");
        return -1; // Store is full
    }

    for (int i = 0; i < store->size; i++) {
        if (store->entries[i].key == key) {
            store->entries[i].value = value; // Update value by key
            store->entries[i].last_update = last_update; // Update last update timestamp
            return 0; // Successfully updated
        }
    }

    // Add new entry
    store->entries[store->size].key = key;
    store->entries[store->size].value = value;
    store->entries[store->size].last_update = last_update;
    store->size++;
    return 0; // Successfully added
}

// Поиск значения по ключу
KeyValue* get_entry(KeyValueStore *store, __u32 key) {
    for (int i = 0; i < store->size; i++) {
        if (store->entries[i].key == key) {
            return &store->entries[i]; // Return pointer to entry
        }
    }
    return NULL; // Key not found
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
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

    // Set up libbpf errors and debug info callback
    libbpf_set_print(libbpf_print_fn);

    // Open BPF application
    skel = cpu_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = cpu_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Attach tracepoint handler
    err = cpu_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Tracking CPU usage. Press Ctrl+C to stop.\n");

    while (1) {
        __u32 pid = 0, next_pid;
        __u64 value;
        __u64 current_time = bpf_ktime_get_ns();
        __u64 total_time = 0;

        // Traverse all process entries in BPF map
        while (bpf_map_get_next_key(bpf_map__fd(skel->maps.cpu_times), &pid, &next_pid) == 0) {
            if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.cpu_times), &next_pid, &value) == 0) {
                KeyValue *entry = get_entry(&store, next_pid);
                if (entry) {
                    // Calculate delta time (time since last update)
                    __u64 delta_time = value - entry->value;
                    __u64 elapsed = current_time - entry->last_update;
                    // Update value in store
                    add_entry(&store, next_pid, delta_time, current_time);
                } else {
                    // First entry for this PID
                    add_entry(&store, next_pid, value, current_time);
                }
                total_time += value;
            }
            pid = next_pid;
        }

        // Calculate and print CPU usage percentages
        printf("Total CPU time in last %d seconds: %llu ns\n", INTERVAL, total_time);
        for (int i = 0; i < store.size; i++) {
            __u64 percent = (total_time > 0) ? (store.entries[i].value * 100) / total_time : 0;
            printf("Process %u used %llu ns of CPU time, which is %llu%% of total\n", store.entries[i].key, store.entries[i].value, percent);
        }

        sleep(INTERVAL);
    }

cleanup:
    cpu_bpf__destroy(skel);
    return -err;
}