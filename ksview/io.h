#ifndef _KSVIEW__IO_H
#define _KSVIEW__IO_H

#define IO_SUCCESS 0
#define IO_ERROR -1
#define IO_FILE_NOT_FOUND -404

int file_load(const char *fname, uint8_t **buf, size_t *len);
#endif
