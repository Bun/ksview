#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#include "io.h"


#define BLOCK_SIZE 4096


int file_load(const char *fname, uint8_t **buf, size_t *len)
{
    int fd, ret = IO_SUCCESS;
    size_t offset = 0;
    size_t tmp_len = 0;
    uint8_t *tmp_buf = NULL;

    if ((fd = open(fname, O_RDONLY)) < 0) {
        if (errno == 2)
            return IO_FILE_NOT_FOUND;
        return IO_ERROR;
    }

    tmp_len = BLOCK_SIZE;
    tmp_buf = malloc(tmp_len);

    for (;;) {
        ssize_t r;
        size_t remaining;

        remaining = tmp_len - offset;

        if (!remaining) {
            uint8_t *ptr;
            tmp_len += BLOCK_SIZE;

            if (!(ptr = realloc(tmp_buf, tmp_len))) {
                ret = -1;
                break;
            }

            tmp_buf = ptr;
            remaining = tmp_len - offset;
        }

        r = read(fd, tmp_buf + offset, remaining);

        if (r < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;

            ret = IO_ERROR;
            break;
        } else if (!r)
            break;

        offset += r;
    }

    close(fd);

    if (ret == 0) {
        *buf = tmp_buf;
        *len = offset;
    } else {
        if (tmp_buf) free(tmp_buf);
    }

    return ret;
}
