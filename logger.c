#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>

#define LOG_DIR "/var/log/os-ids"
#define LOG_FILE "/var/log/os-ids/alerts.log"

void log_info(const char *format, ...) {
    struct stat st;
    if (stat(LOG_DIR, &st) == -1) {
        if (mkdir(LOG_DIR, 0755) != 0 && errno != EEXIST) {
            perror("Failed to create log directory");
            return;
        }
    }

    FILE *f = fopen(LOG_FILE, "a");
    if (!f) {
        perror("Could not open log file");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    // Write to file
    fprintf(f, "[%s] %s\n", timestamp, message);
    fclose(f);
}