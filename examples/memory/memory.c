// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#define PROC_PATH "/proc"
#define BUFFER_SIZE 256
#define INTERVAL 5

void get_memory_usage(int pid) {
    char path[BUFFER_SIZE];
    FILE *file;
    char line[BUFFER_SIZE];
    snprintf(path, sizeof(path), PROC_PATH "/%d/status", pid);


    file = fopen(path, "r");
    if (!file) {
        // Ошибка может возникать для завершенных процессов или недоступных файлов
        perror("fopen");
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "VmPSS:", 6) == 0) {
            printf("PID: %d, %s", pid, line + 6);
            break;
        }
    }

    fclose(file);
}

void scan_processes() {
    struct dirent *entry;
    DIR *proc_dir;
    proc_dir = opendir(PROC_PATH);

    if (!proc_dir) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            int pid = atoi(entry->d_name);
            if (pid > 0) {
                get_memory_usage(pid);
            }
        }
    }

    closedir(proc_dir);
}

int main() {
    while (1) {
        scan_processes();
        sleep(INTERVAL);
    }

    return 0;
}