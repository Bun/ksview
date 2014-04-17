#ifndef _KSVIEW__CRYPTO_H
#define _KSVIEW__CRYPTO_H

// Wrapper for the OpenSSL API


#include <openssl/aes.h>
#include <openssl/sha.h>


// AES-256

#define aes256_init(ctx, key) \
    AES_KEY ctx = {0}; \
    AES_set_encrypt_key(key, 256, &x);

#define aes_ecb_encrypt(ctx, src, dst) \
    AES_ecb_encrypt(src, dst, &ctx, 1);

void aes256_cbc_decrypt(const uint8_t *key, uint8_t *iv, uint8_t *data,
                        size_t sz);



// SHA-256

#define SHA256_DIGEST_LEN 32

#define sha256_digest SHA256

#define sha256_init(ctx) \
    SHA256_CTX ctx = {0}; \
    SHA256_Init(&ctx);

#define sha256_update(ctx, data, sz) \
    SHA256_Update(&ctx, data, sz);

#define sha256_final(ctx, digest) \
    SHA256_Final(digest, &ctx);


#endif
