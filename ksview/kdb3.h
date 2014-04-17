#ifndef _KSVIEW__KDB3_H
#define _KSVIEW__KDB3_H
#define KDB3_KEY_LENGTH 32

#define KDB3_SHA2 2
#define KDB3_CIPHER_AES256_CBC 2


typedef struct __attribute__((__packed__)) {
    uint32_t signature1;
    uint32_t signature2;
    uint32_t flags;
    uint32_t version;
    uint8_t seed_final[16];
    uint8_t iv[16];
    uint32_t group_count;
    uint32_t entry_count;
    uint8_t hash[32];
    uint8_t seed_trans[32];
    uint32_t key_rounds;
} kdb3_header_t;

#define KDB3_HEADER_LEN (sizeof(kdb3_header_t))

#define KDB3_SUCCESS 0
#define KDB3_ERROR -1
#define KDB3_UNSUPPORTED -2
#define KDB3_KEY_VERIFY_FAILED -3
#define KDB3_HEADER_SIZE_INVALID -4
#define KDB3_BODY_SIZE_INVALID -5
#define KDB3_FIELD_SIZE_INVALID -6
#define KDB3_TRAILING_DATA -7



typedef struct {
    int x;
} kdb3_group_t;

typedef struct {
    int x;
} kdb3_entry_t;


struct _kdb3_t {
    uint8_t *data;
    size_t size;
    size_t body_size;

    kdb3_header_t *hdr;
    kdb3_group_t **groups;
    kdb3_entry_t **entries;
};

typedef struct _kdb3_t *kdb3_t;

int kdb3_transform_password(const char *password,
                            uint8_t key[KDB3_KEY_LENGTH]);
int kdb3_import(kdb3_t *db, const char *filename, const uint8_t key[KDB3_KEY_LENGTH]);
int kdb3_print_header(const kdb3_t db);
int kdb3_print(const kdb3_t db);
int kdb3_deinit(kdb3_t db);
#endif
