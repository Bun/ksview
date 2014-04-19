#ifndef _KSVIEW__KDB3_H
#define _KSVIEW__KDB3_H
#define KDB3_KEY_LENGTH 32

#define KDB3_SHA2 2
#define KDB3_CIPHER_AES256_CBC 2


typedef struct __attribute__((__packed__)) {
    uint64_t signature;
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
#define KDB3_INVALID_SIGNATURE -8

// Entry fields
#define KDB3_ENTRY_UUID        0x0001
#define KDB3_ENTRY_GROUP_ID    0x0002
#define KDB3_ENTRY_IMAGE_ID    0x0003
#define KDB3_ENTRY_TITLE       0x0004
#define KDB3_ENTRY_URL         0x0005
#define KDB3_ENTRY_USERNAME    0x0006
#define KDB3_ENTRY_PASSWORD    0x0007
#define KDB3_ENTRY_COMMENT     0x0008
#define KDB3_ENTRY_CREATED     0x0009
#define KDB3_ENTRY_MODIFIED    0x000A
#define KDB3_ENTRY_ACCESSED    0x000B
#define KDB3_ENTRY_EXPIRES     0x000C
#define KDB3_ENTRY_BINARY_DESC 0x000D
#define KDB3_ENTRY_BINARY      0x000E
#define KDB3_ENTRY_END         0xFFFF

// Group fields
#define KDB3_GROUP_ID       0x0001
#define KDB3_GROUP_TITLE    0x0002
#define KDB3_GROUP_IMAGE_ID 0x0007
#define KDB3_GROUP_LEVEL    0x0008
#define KDB3_GROUP_FLAGS    0x0009
#define KDB3_GROUP_END      0xFFFF


typedef struct {
    uint32_t id;
    uint32_t image_id;
    uint32_t flags;
    uint16_t level;
    const char *title;
} kdb3_group_t;

typedef struct {
    uint8_t uuid[16];
    uint32_t group_id;
    uint32_t image_id;
    const char *title;
    const char *url;
    const char *username;
    const char *password;
    const char *comment;

    time_t created;
    time_t modified;
    time_t accessed;
    time_t expires;
} kdb3_entry_t;


struct _kdb3_t {
    uint8_t *data;
    size_t size;
    size_t body_size;

    kdb3_header_t *hdr;
    kdb3_group_t *groups;
    kdb3_entry_t *entries;
};

typedef struct _kdb3_t *kdb3_t;

int kdb3_transform_password(const char *password,
                            uint8_t key[KDB3_KEY_LENGTH]);
int kdb3_import(kdb3_t *db, const char *filename, const uint8_t key[KDB3_KEY_LENGTH]);
int kdb3_print_header(const kdb3_t db);
int kdb3_print(const kdb3_t db);
int kdb3_deinit(kdb3_t db);
#endif
