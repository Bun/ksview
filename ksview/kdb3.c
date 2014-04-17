#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kdb3.h"
#include "io.h"
#include "crypto.h"


static void _dump_text(uint8_t *buf, size_t sz)
{
    for (size_t i = 0; i < sz; i++) {
        if (buf[i] <= 0x20 || buf[i] >= 0x7F || buf[i] == '\\')
            printf("\\x%02X", buf[i]);
        else
            printf("%c", buf[i]);

    }

    puts("");
}


// -- Crypto ------------------------------------------------------------------

/* Applies the KDB3 key transformation on the SHA-256 digest of the master key.
 */
static
void _kdb3_key_transform(const uint8_t master_key[SHA256_DIGEST_LEN],
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
    fprintf(stderr, "key rounds:  %d\n", db->hdr->key_rounds);
    return KDB3_SUCCESS;
}


/* Parse the header and decrypt the body of the database
 */
int _kdb3_parse(kdb3_t db, const uint8_t raw_master_key[SHA256_DIGEST_LEN])
{
    //uint8_t master_key[SHA256_DIGEST_LEN] = {0};
    uint8_t temp[SHA256_DIGEST_LEN] = {0};
    int cipher;

    db->hdr = (kdb3_header_t *) db->data;

    /* XXX: Check signature and version */

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

    if (memcmp(db->hdr->hash, temp, SHA256_DIGEST_LEN) != 0) {
        fprintf(stderr, "Key incorrect\n");
        return KDB3_KEY_VERIFY_FAILED;
    }

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

/*
 */
int kdb3_print(const kdb3_t db)
{
    const size_t FIELD_HEADER_LEN = sizeof(uint16_t) + sizeof(uint32_t);

    uint8_t *ptr = db->data + KDB3_HEADER_LEN;
    size_t remainder = db->body_size;

    printf("GROUPS\n");

    for (uint32_t group = 0; group < db->hdr->group_count; ) {
        uint16_t field_type;
        uint32_t field_size;

        if (remainder < FIELD_HEADER_LEN)
            return KDB3_FIELD_SIZE_INVALID;

        field_type = *(uint16_t *) ptr; ptr += sizeof(uint16_t);
        field_size = *(uint32_t *) ptr; ptr += sizeof(uint32_t);
        remainder -= FIELD_HEADER_LEN;
        printf("[%04X=%d]", field_type, field_size);

        if (remainder < field_size)
            return KDB3_FIELD_SIZE_INVALID;

        _dump_text(ptr, field_size);
        ptr += field_size;
        remainder -= field_size;

        if (field_type == 0xFFFF) {
            printf("\nEND OF GROUP\n");
            group++;
        }
    }

    printf("ENTRIES\n");

    for (uint32_t entry = 0; entry < db->hdr->entry_count; ) {
        uint16_t field_type;
        uint32_t field_size;

        if (remainder < FIELD_HEADER_LEN)
            return KDB3_FIELD_SIZE_INVALID;

        field_type = *(uint16_t *) ptr; ptr += sizeof(uint16_t);
        field_size = *(uint32_t *) ptr; ptr += sizeof(uint32_t);
        remainder -= FIELD_HEADER_LEN;
        printf("[%04X=%d]", field_type, field_size);

        if (remainder < field_size)
            return KDB3_FIELD_SIZE_INVALID;

        _dump_text(ptr, field_size);
        ptr += field_size;
        remainder -= field_size;

        if (field_type == 0xFFFF) {
            printf("\nEND OF ENTRY\n");
            entry++;
        }
    }

    // Not an error per se, but probably indicates corruption
    return remainder == 0 ? 0 : KDB3_TRAILING_DATA;
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

        free(db);
    }

    return KDB3_SUCCESS;
}
