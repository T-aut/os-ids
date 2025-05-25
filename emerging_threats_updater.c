#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

int rev_version = 0;

void trim(char *str) {
    char *end;

    while (isspace(*str)) str++;

    if (*str == 0) return;

    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;

    end[1] = '\0';
}

char** update_ip_set(char** cidrs, int MAX_SIZE, int* length) {
    system("[ -f /tmp/emerging-Block-IPs.txt ] || wget -P /tmp/ https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt");

    FILE *fp = fopen("/tmp/emerging-Block-IPs.txt", "r");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    // TODO: deal with rev_version

    char line[256];
    int index = 0;

    while (fgets(line, sizeof(line), fp)) {
        trim(line);

        if (line[0] == '\0' || line[0] == '#' || line[0] == '\n') continue;

        if (strchr(line, '/') != NULL) {
            cidrs[index] = strdup(line);
        } else {
            char *with_cidr = malloc(strlen(line) + 4);
            sprintf(with_cidr, "%s/32", line);
            cidrs[index] = with_cidr;
        }

        index++;
        if (index >= MAX_SIZE) break;
    }

    fclose(fp);
    *length = index;
    return cidrs;
}