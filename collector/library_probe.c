/* Record a controlled application's public readdir64 results. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3 || (strcmp(argv[2], "full") && strcmp(argv[2], "early")))
        return 2;
    printf("PID %jd\n", (intmax_t)getpid());
    if (fflush(stdout) || getchar() != '\n')
        return 2;

    DIR *stream = opendir(argv[1]);
    if (!stream) {
        perror("opendir");
        return 1;
    }
    int status = 0;
    size_t count = 0;
    for (;;) {
        errno = 0;
        const struct dirent64 *entry = readdir64(stream);
        if (!entry) {
            if (errno) {
                perror("readdir64");
                status = 1;
            } else {
                puts("END eof");
            }
            break;
        }
        printf("ENTRY %" PRIu64 " %u ", (uint64_t)entry->d_ino, (unsigned)entry->d_type);
        for (size_t i = 0; i < strlen(entry->d_name); i++)
            printf("%02x", (unsigned)(unsigned char)entry->d_name[i]);
        putchar('\n');
        if (!strcmp(argv[2], "early") && ++count == 12) {
            puts("END early_close");
            break;
        }
    }
    if (closedir(stream)) {
        perror("closedir");
        status = 1;
    }
    return status || ferror(stdout);
}
