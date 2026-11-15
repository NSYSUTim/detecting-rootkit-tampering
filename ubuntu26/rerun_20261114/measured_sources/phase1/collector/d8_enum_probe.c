/* Count every record returned by getdents64 for one complete enumeration. */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

struct d8_linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

int main(int argc, char **argv)
{
    char gate;
    char buffer[65536];
    size_t total = 0;
    int fd;

    if (argc != 2) {
        fprintf(stderr, "usage: %s DIRECTORY\n", argv[0]);
        return 2;
    }
    if (read(STDIN_FILENO, &gate, 1) != 1) {
        fputs("failed to receive start gate\n", stderr);
        return 2;
    }
    fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open: %s\n", strerror(errno));
        return 2;
    }

    for (;;) {
        long result = syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
        long offset = 0;

        if (result < 0) {
            fprintf(stderr, "getdents64: %s\n", strerror(errno));
            close(fd);
            return 2;
        }
        if (result == 0)
            break;
        while (offset < result) {
            struct d8_linux_dirent64 *entry =
                (struct d8_linux_dirent64 *)(buffer + offset);
            size_t header = offsetof(struct d8_linux_dirent64, d_name);
            size_t room;

            if (entry->d_reclen < header + 1 ||
                offset + entry->d_reclen > result) {
                fputs("malformed getdents64 record\n", stderr);
                close(fd);
                return 2;
            }
            room = entry->d_reclen - header;
            if (strnlen(entry->d_name, room) == room) {
                fputs("unterminated getdents64 name\n", stderr);
                close(fd);
                return 2;
            }
            total++;
            offset += entry->d_reclen;
        }
    }
    close(fd);
    printf("%zu\n", total);
    return 0;
}
