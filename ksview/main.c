#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

#include "kdb3.h"
#include "getpass.h"

#define MAX_PASSPHRASE 1024


int main(int argc, char **argv)
{
    uint8_t key[KDB3_KEY_LENGTH];
    char passphrase[MAX_PASSPHRASE];
    kdb3_t db;

    if (password_get(passphrase, MAX_PASSPHRASE) < 0) {
        return EXIT_FAILURE;
    }

    kdb3_transform_password(passphrase, key);
    bzero(passphrase, MAX_PASSPHRASE);

    if (kdb3_import(&db, argv[1], key) < 0) {
        return EXIT_FAILURE;
    }

    bzero(key, KDB3_KEY_LENGTH);

    kdb3_print_header(db);
    kdb3_print(db);
    kdb3_deinit(db);
    return EXIT_SUCCESS;
}
