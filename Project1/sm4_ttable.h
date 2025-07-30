#ifndef SM4_TTABLE_H
#define SM4_TTABLE_H

#include <stdint.h>
#include <stddef.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_ROUNDS 32

// 声明常量（在源文件中定义）
extern const uint8_t SM4_SBOX[256];
extern const uint32_t FK[4];
extern const uint32_t CK[32];

typedef struct {
    uint32_t rk[SM4_ROUNDS];
    uint32_t T0[256], T1[256], T2[256], T3[256];
} SM4_TTABLE_CTX;

// 函数声明
void sm4_ttable_init(SM4_TTABLE_CTX *ctx, const uint8_t key[SM4_KEY_SIZE]);
void sm4_ttable_crypt(const SM4_TTABLE_CTX *ctx, const uint8_t *input, 
                     uint8_t *output, size_t length, int encrypt);
size_t sm4_ttable_cbc_encrypt(SM4_TTABLE_CTX *ctx, const uint8_t iv[SM4_BLOCK_SIZE],
                            const uint8_t *plaintext, uint8_t *ciphertext, size_t length);
size_t sm4_ttable_cbc_decrypt(SM4_TTABLE_CTX *ctx, const uint8_t iv[SM4_BLOCK_SIZE],
                            const uint8_t *ciphertext, uint8_t *plaintext, size_t length);

#endif // SM4_TTABLE_H