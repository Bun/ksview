#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kdb3.h"
#include "io.h"
#include "crypto.h"


const uint64_t KDB3_SIGNATURE = UINT64_C(0xB54BFB659AA2D903);


// -- Crypto ------------------------------------------------------------------

/* Applies the KDB3 key transformation on the SHA-256 digest of the master key.
 */
static void
_kdb3_key_transform(const uint8_t master_key[SHA256_DIGEST_LEN],
                    uint8_t dst[SHA256_DIGEST_LEN],
                    const uint8_t rounds_key[32],
                    uint32_t rounds,
                    const uint8_t final_seed[16])
{
    // Multiple ECB rounds on both halves of the master key
    aes256_init(x, rounds_key);
    memcpy(dst,      master_key,      16);
    memcpy(dst + 16, master_key + 16, 16);

    for (uint32_t i = 0; i < rounds; i++) {
        aes_ecb_encrypt(x, dst,      dst);
        aes_ecb_encrypt(x, dst + 16, dst + 16);
    }

    sha256_digest(dst, SHA256_DIGEST_LEN, dst);

    // Once more, for good luck
    sha256_init(s);
    sha256_update(s, final_seed, 16);
    sha256_update(s, dst, SHA256_DIGEST_LEN);
    sha256_final(s, dst);
}


// -- Parsing -----------------------------------------------------------------

/* Compute the base master key from a passphrase.
 *
 * This is the first step in the key transformation phase.
 */
int kdb3_transform_password(const char *password,
                            uint8_t key[SHA256_DIGEST_LEN])
{
    sha256_digest((const uint8_t *) password, strlen(password), key);
    return KDB3_SUCCESS;
}


/*
 */
int kdb3_print_header(const kdb3_t db)
{
    fprintf(stderr, "Size:        %zu\n", db->size);
    fprintf(stderr, "Header size: %zu\n", KDB3_HEADER_LEN);
    fprintf(stderr, "Body size:   %zu\n", db->body_size);

    fprintf(stderr, "Version:     %d\n", db->hdr->version);
    fprintf(stderr, "Flags:       %d\n", db->hdr->flags);
    fprintf(stderr, "Group count: %d\n", db->hdr->group_count);
    fprintf(stderr, "Entry count: %d\n", db->hdr->entry_count);
    fprintf(stderr, "Key rounds:  %d\n", db->hdr->key_rounds);
    return KDB3_SUCCESS;
}


/* Parse the header and decrypt the body of the database
 */
static int
_kdb3_parse_header(kdb3_t db, const uint8_t raw_master_key[SHA256_DIGEST_LEN])
{
    //uint8_t master_key[SHA256_DIGEST_LEN] = {0};
    uint8_t temp[SHA256_DIGEST_LEN] = {0};
    int cipher;

    db->hdr = (kdb3_header_t *) db->data;

    if (db->hdr->signature != KDB3_SIGNATURE)
        return KDB3_INVALID_SIGNATURE;

    _kdb3_key_transform(raw_master_key, temp, db->hdr->seed_trans,
                        db->hdr->key_rounds, db->hdr->seed_final);

    cipher = 0;

    if (db->hdr->flags & KDB3_CIPHER_AES256_CBC)
        cipher = KDB3_CIPHER_AES256_CBC;

    switch (cipher) {
    case KDB3_CIPHER_AES256_CBC:
        aes256_cbc_decrypt(temp, db->hdr->iv,
                           db->data + KDB3_HEADER_LEN,
                           db->size - KDB3_HEADER_LEN);
        db->body_size = db->size - db->data[db->size - 1] - KDB3_HEADER_LEN;
        break;

    // Other modes include Twofish and RC4
    default:
        return KDB3_UNSUPPORTED;
    }

    bzero(temp, SHA256_DIGEST_LEN);

    // Check if removing the padding results in an impossible data size
    // Note that this may simply be a symptom of a bad key
    if (!db->body_size || db->body_size > (db->size - KDB3_HEADER_LEN)) {
        db->body_size = 0;
        return KDB3_BODY_SIZE_INVALID;
    }

    // Verify key by hashing the body
    sha256_digest(db->data + KDB3_HEADER_LEN, db->body_size, temp);

    if (memcmp(db->hdr->hash, temp, SHA256_DIGEST_LEN) != 0)
        return KDB3_KEY_VERIFY_FAILED;

    return KDB3_SUCCESS;
}


/* Parse the groups and entries.
 *
 * TODO:
 * - Cache the group hierarchy
 * - Cache which group an entry belongs to
 * - Consider storing the field_size per field as well
 */
static int
_kdb3_parse_body(kdb3_t db)
{
    const size_t FIELD_HEADER_LEN = sizeof(uint16_t) + sizeof(uint32_t);

    uint8_t *ptr = db->data + KDB3_HEADER_LEN;
    size_t remainder = db->body_size;

    db->groups = calloc(db->hdr->group_count, sizeof(kdb3_group_t));
    db->entries = calloc(db->hdr->entry_count, sizeof(kdb3_entry_t));

    if (!db->groups || !db->entries)
        return KDB3_ERROR;

#define _UINT16_FIELD(id, fname) \
    case id: \
        if (field_size != 2)  \
            return KDB3_ERROR; \
        fname = *(uint16_t *) ptr; \
        break;

#define _UINT32_FIELD(id, fname) \
    case id: \
        if (field_size != 4)  \
            return KDB3_ERROR; \
        fname = *(uint16_t *) ptr; \
        break;

#define _TIME_FIELD(id, fname) \
    case id: \
        if (field_size != 5)  \
            return KDB3_ERROR; \
        fname = 0xDEADBEEF; /* TODO */ \
        break;

#define _STRING_FIELD(id, fname) \
    case id: \
        if (field_size) { \
            /* Must have trailing nul*/ \
            if (ptr[field_size - 1]) \
                return KDB3_ERROR; \
            fname = (const char *) ptr; \
        } \
        break;


    for (uint32_t group = 0; group < db->hdr->group_count; ) {
        uint16_t field_type;
        uint32_t field_size;

        if (remainder < FIELD_HEADER_LEN)
            return KDB3_FIELD_SIZE_INVALID;

        field_type = *(uint16_t *) ptr; ptr += sizeof(uint16_t);
        field_size = *(uint32_t *) ptr; ptr += sizeof(uint32_t);
        remainder -= FIELD_HEADER_LEN;

        if (remainder < field_size)
            return KDB3_FIELD_SIZE_INVALID;

        switch (field_type) {
        case KDB3_GROUP_END:
            if (field_size != 0) return KDB3_ERROR;
            group++;
            break;

        _UINT32_FIELD(KDB3_GROUP_ID,       db->groups[group].id)
        _UINT32_FIELD(KDB3_GROUP_IMAGE_ID, db->groups[group].image_id)
        _UINT16_FIELD(KDB3_GROUP_LEVEL,    db->groups[group].level)
        _STRING_FIELD(KDB3_GROUP_TITLE,    db->groups[group].title)
        _UINT32_FIELD(KDB3_GROUP_FLAGS,    db->groups[group].flags)

        case 0x0003:
        case 0x0004:
        case 0x0005:
        case 0x0006:
            break;

        default:
            fprintf(stderr, "Unhandled group field: %u (%u)\n", field_type,
                    field_size);
            break;
        }

        ptr += field_size;
        remainder -= field_size;
    }

    for (uint32_t entry = 0; entry < db->hdr->entry_count; ) {
        uint16_t field_type;
        uint32_t field_size;

        if (remainder < FIELD_HEADER_LEN)
            return KDB3_FIELD_SIZE_INVALID;

        field_type = *(uint16_t *) ptr; ptr += sizeof(uint16_t);
        field_size = *(uint32_t *) ptr; ptr += sizeof(uint32_t);
        remainder -= FIELD_HEADER_LEN;

        if (remainder < field_size)
            return KDB3_FIELD_SIZE_INVALID;

        switch (field_type) {
        case KDB3_ENTRY_END:
            if (field_size != 0) return KDB3_ERROR;
            entry++;
            break;

        case KDB3_ENTRY_UUID:
            if (field_size != 16) return KDB3_ERROR;
            memcpy(db->entries[entry].uuid, ptr, 16);
            break;

        _UINT32_FIELD(KDB3_ENTRY_GROUP_ID, db->entries[entry].group_id)
        _UINT32_FIELD(KDB3_ENTRY_IMAGE_ID, db->entries[entry].image_id)
        _STRING_FIELD(KDB3_ENTRY_TITLE,    db->entries[entry].title)
        _STRING_FIELD(KDB3_ENTRY_PASSWORD, db->entries[entry].password)
        _STRING_FIELD(KDB3_ENTRY_USERNAME, db->entries[entry].username)
        _STRING_FIELD(KDB3_ENTRY_URL,      db->entries[entry].url)
        _STRING_FIELD(KDB3_ENTRY_COMMENT,  db->entries[entry].comment)
        _TIME_FIELD(KDB3_ENTRY_CREATED,    db->entries[entry].created)
        _TIME_FIELD(KDB3_ENTRY_MODIFIED,   db->entries[entry].modified)
        _TIME_FIELD(KDB3_ENTRY_ACCESSED,   db->entries[entry].accessed)
        _TIME_FIELD(KDB3_ENTRY_EXPIRES,    db->entries[entry].expires)

        case KDB3_ENTRY_BINARY:
        case KDB3_ENTRY_BINARY_DESC:
            break;

        default:
            fprintf(stderr, "Unhandled entry field: %u (%u)\n", field_type, field_size);
            break;
        }

        ptr += field_size;
        remainder -= field_size;
    }

#if 0
    // Not an error per se, but probably indicates corruption
    // Should we report this?
    return remainder == 0 ? KDB3_SUCCESS : KDB3_TRAILING_DATA;
#else
    return KDB3_SUCCESS;
#endif
}


/*
 */
static int
_kdb3_parse(kdb3_t db, const uint8_t key[SHA256_DIGEST_LEN])
{
    int ret;

    if ((ret = _kdb3_parse_header(db, key)) < 0)
        return ret;

    if ((ret = _kdb3_parse_body(db)) < 0)
        return ret;

    return KDB3_SUCCESS;
}


/* Import a KDB3 file
 */
int kdb3_import(kdb3_t *db,
                const char *filename,
                const uint8_t key[SHA256_DIGEST_LEN])
{
    int ret = 0;
    kdb3_t dbi;

    if (!(dbi = calloc(1, sizeof(struct _kdb3_t))))
        return KDB3_ERROR;

    if ((ret = file_load(filename, &dbi->data, &dbi->size)) < 0)
        goto failed;

    if (dbi->size < KDB3_HEADER_LEN) {
        ret = KDB3_HEADER_SIZE_INVALID;
    } else {
        ret = _kdb3_parse(dbi, key);
    }

failed:
    if (ret < 0) {
        if (dbi)
            kdb3_deinit(dbi);
    } else {
        *db = dbi;
    }

    return ret;
}


// ----------------------------------------------------------------------------

static inline size_t max(size_t a, size_t b) { return a > b ? a : b; }

/* Print all the entries in the database
 *
 * TODO:
 * - Unicode support for column width
 * - Ignore meta rows
 */
int kdb3_print(const kdb3_t db)
{
    char format[2048];
    int column_width[5] = {0};

    for (uint32_t group = 0; group < db->hdr->group_count; group++) {
        column_width[0] = max(strlen(db->groups[group].title), column_width[0]);
    }

    for (uint32_t entry = 0; entry < db->hdr->entry_count; entry++) {
        column_width[1] = max(strlen(db->entries[entry].title), column_width[1]);
        column_width[2] = max(strlen(db->entries[entry].username), column_width[2]);
        column_width[3] = max(strlen(db->entries[entry].url), column_width[3]);
        column_width[4] = max(strlen(db->entries[entry].password), column_width[4]);
    }

    // Beware: naive, slow implementation ahead
    snprintf(format, sizeof(format), "%%-%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds\n",
             column_width[0], column_width[1], column_width[2],
             column_width[3], column_width[4]);

    for (uint32_t entry = 0; entry < db->hdr->entry_count; entry++) {
        const char *group_title = NULL;

        for (uint32_t group = 0; group < db->hdr->group_count; group++) {
            if (db->groups[group].id == db->entries[entry].group_id) {
                group_title = db->groups[group].title;
                break;
            }
        }

        printf(format, group_title,
               db->entries[entry].title,
               db->entries[entry].username,
               db->entries[entry].url,
               db->entries[entry].password);
    }

    return KDB3_SUCCESS;
}


/* Release all memory and clear sensitive memory
 */
int kdb3_deinit(kdb3_t db)
{
    if (db) {
        if (db->data) {
            bzero(db->data, db->size);
            free(db->data);
        }

        if (db->groups)
            free(db->groups);

        if (db->entries)
            free(db->entries);

        free(db);
    }

    return KDB3_SUCCESS;
}
