#include <stdio.h>
#include <stdint.h>
#include <string.h>

// T-table优化实现
typedef struct {
    uint32_t T0[256];  // S盒+线性变换L的预计算结果
    uint32_t T1[256];
    uint32_t T2[256];
    uint32_t T3[256];
} SM4_TTABLE;

// 初始化T-table
void init_ttable(SM4_TTABLE* ttable) {
    for (int i = 0; i < 256; i++) {
        uint32_t a = SM4_SBOX[i];
        // 应用线性变换L的各个部分
        ttable->T0[i] = a ^ rol(a, 2) ^ rol(a, 10) ^ rol(a, 18) ^ rol(a, 24);
        ttable->T1[i] = rol(ttable->T0[i], 8);
        ttable->T2[i] = rol(ttable->T0[i], 16);
        ttable->T3[i] = rol(ttable->T0[i], 24);
    }
}

// T-table优化的轮函数
static uint32_t T_ttable(const SM4_TTABLE* ttable, uint32_t X) {
    return ttable->T0[(X >> 24) & 0xFF] ^ 
           ttable->T1[(X >> 16) & 0xFF] ^ 
           ttable->T2[(X >> 8) & 0xFF] ^ 
           ttable->T3[X & 0xFF];
}

// T-table优化的分组加密/解密
void sm4_block_crypt_ttable(const uint8_t input[16], uint8_t output[16], 
                           const uint32_t rk[32], const SM4_TTABLE* ttable, int encrypt) {
    uint32_t X[4];
    
    // 输入分组处理
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)input[4*i] << 24) |
               ((uint32_t)input[4*i+1] << 16) |
               ((uint32_t)input[4*i+2] << 8) |
               input[4*i+3];
    }
    
    // 32轮Feistel网络
    for (int r = 0; r < 32; r++) {
        uint32_t rk_val = encrypt ? rk[r] : rk[31-r];
        uint32_t input_val = X[1] ^ X[2] ^ X[3] ^ rk_val;
        uint32_t new_X = X[0] ^ T_ttable(ttable, input_val);
        
        // 状态更新
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = new_X;
    }
    
    // 输出处理
    for (int i = 0; i < 4; i++) {
        output[4*i]   = (X[3-i] >> 24) & 0xFF;
        output[4*i+1] = (X[3-i] >> 16) & 0xFF;
        output[4*i+2] = (X[3-i] >> 8) & 0xFF;
        output[4*i+3] = X[3-i] & 0xFF;
    }
}

// 完整的T-table优化实现
int sm4_crypt_ttable(const uint8_t* input, int in_len, uint8_t* output, 
                    const uint8_t key[16], int encrypt) {
    static SM4_TTABLE ttable;
    static int initialized = 0;
    uint32_t rk[32];
    
    // 初始化T-table（只需一次）
    if (!initialized) {
        init_ttable(&ttable);
        initialized = 1;
    }
    
    // 密钥扩展
    generate_round_keys(key, rk);
    
    // 处理数据块
    int out_len = 0;
    for (int i = 0; i < in_len; i += 16) {
        uint8_t block[16];
        int block_len = (in_len - i) > 16 ? 16 : (in_len - i);
        
        if (encrypt && block_len < 16) {
            // 加密填充
            memcpy(block, input + i, block_len);
            block_len = pkcs7_pad(block, block_len, 16);
        } else {
            memcpy(block, input + i, block_len);
        }
        
        sm4_block_crypt_ttable(block, output + out_len, rk, &ttable, encrypt);
        out_len += 16;
    }
    
    // 解密时去除填充
    if (!encrypt) {
        out_len = pkcs7_unpad(output, out_len);
    }
    
    return out_len;
}

// 性能测试
void benchmark() {
    uint8_t key[16] = {0};
    uint8_t plain[1024] = {0};  // 1KB测试数据
    uint8_t cipher[1024], decrypted[1024];
    SM4_TTABLE ttable;
    
    init_ttable(&ttable);
    
    printf("=== T-table优化性能测试 ===\n");
    
    clock_t start = clock();
    for (int i = 0; i < 10000; i++) {  // 加密10,000次
        sm4_crypt_ttable(plain, 1024, cipher, key, 1);
    }
    double encrypt_time = (double)(clock() - start) / CLOCKS_PER_SEC;
    printf("加密吞吐量: %.2f MB/s\n", (10000.0 * 1024) / (encrypt_time * 1024 * 1024));
    
    start = clock();
    for (int i = 0; i < 10000; i++) {  // 解密10,000次
        sm4_crypt_ttable(cipher, 1024, decrypted, key, 0);
    }
    double decrypt_time = (double)(clock() - start) / CLOCKS_PER_SEC;
    printf("解密吞吐量: %.2f MB/s\n", (10000.0 * 1024) / (decrypt_time * 1024 * 1024));
    
    // 验证结果
    if (memcmp(plain, decrypted, 1024) == 0) {
        printf("加解密验证: PASS\n");
    } else {
        printf("加解密验证: FAIL\n");
    }
}

int main() {
    // 标准测试
    test_sm4();  // 使用之前的基础测试函数
    
    // 性能测试
    benchmark();
    
    return 0;
}