#include <stdint.h>
#include "crypto.h"


// Decrypt the given buffer using AES-256 CBC
void aes256_cbc_decrypt(const uint8_t *key, uint8_t *iv,
                        uint8_t *data, size_t sz)
{
    AES_KEY ctx = {0};
    AES_set_decrypt_key(key, 256, &ctx);
    AES_cbc_encrypt(data, data, sz, &ctx, iv, AES_DECRYPT);
}
