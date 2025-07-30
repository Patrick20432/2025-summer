#include <stdio.h>
#include <stdint.h>
#include <string.h>

// SM4标准S盒 (GB/T 32907-2016)
static const uint8_t SM4_SBOX[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

// 系统参数FK
static const uint32_t FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

// 固定参数CK
static const uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// 循环左移
static uint32_t rol(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// 非线性变换τ
static uint32_t tau(uint32_t A) {
    return (SM4_SBOX[(A >> 24) & 0xFF] << 24) |
           (SM4_SBOX[(A >> 16) & 0xFF] << 16) |
           (SM4_SBOX[(A >> 8) & 0xFF] << 8) |
           SM4_SBOX[A & 0xFF];
}

// 加密线性变换L
static uint32_t L(uint32_t B) {
    return B ^ rol(B, 2) ^ rol(B, 10) ^ rol(B, 18) ^ rol(B, 24);
}

// 密钥扩展线性变换L'
static uint32_t L_prime(uint32_t B) {
    return B ^ rol(B, 13) ^ rol(B, 23);
}

// 加密轮函数T
static uint32_t T(uint32_t A) {
    return L(tau(A));
}

// 密钥扩展函数T'
static uint32_t T_prime(uint32_t A) {
    return L_prime(tau(A));
}

// 密钥扩展算法
void generate_round_keys(const uint8_t master_key[16], uint32_t rk[32]) {
    uint32_t MK[4], K[36];
    
    // 将128位主密钥分为4个32位字
    for (int i = 0; i < 4; i++) {
        MK[i] = ((uint32_t)master_key[4*i] << 24) |
                ((uint32_t)master_key[4*i+1] << 16) |
                ((uint32_t)master_key[4*i+2] << 8) |
                master_key[4*i+3];
    }
    
    // 初始化和密钥异或固定参数
    for (int i = 0; i < 4; i++) {
        K[i] = MK[i] ^ FK[i];
    }
    
    // 生成32个轮密钥
    for (int i = 0; i < 32; i++) {
        uint32_t temp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i];
        K[i+4] = K[i] ^ T_prime(temp);
        rk[i] = K[i+4];
    }
}

// SM4分组加密/解密核心函数
void sm4_block_crypt(const uint8_t input[16], uint8_t output[16], const uint32_t rk[32], int encrypt) {
    uint32_t X[4];
    
    // 将128位块拆分为4个32位字
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
        uint32_t t_val = T(input_val);
        uint32_t new_X = X[0] ^ t_val;
        
        // 状态更新
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = new_X;
    }
    
    // 最终反序输出
    for (int i = 0; i < 4; i++) {
        output[4*i]   = (X[3-i] >> 24) & 0xFF;
        output[4*i+1] = (X[3-i] >> 16) & 0xFF;
        output[4*i+2] = (X[3-i] >> 8) & 0xFF;
        output[4*i+3] = X[3-i] & 0xFF;
    }
}

// PKCS7填充
int pkcs7_pad(uint8_t *buf, int len, int block_size) {
    int pad_len = block_size - (len % block_size);
    if (pad_len == 0) pad_len = block_size;
    
    for (int i = 0; i < pad_len; i++) {
        buf[len + i] = pad_len;
    }
    return len + pad_len;
}

// PKCS7去填充
int pkcs7_unpad(uint8_t *buf, int len) {
    if (len <= 0) return 0;
    
    int pad_len = buf[len-1];
    if (pad_len > len) return -1; // 无效填充
    
    for (int i = len - pad_len; i < len; i++) {
        if (buf[i] != pad_len) return -1;
    }
    return len - pad_len;
}

// SM4加密/解密函数
int sm4_crypt(const uint8_t *input, int in_len, uint8_t *output, const uint8_t key[16], int encrypt) {
    uint32_t rk[32];
    uint8_t block[16];
    int out_len = 0;
    
    // 密钥扩展
    generate_round_keys(key, rk);
    
    // 处理数据块
    for (int i = 0; i < in_len; i += 16) {
        int block_len = (in_len - i) > 16 ? 16 : (in_len - i);
        
        // 加密时需要填充最后一个块
        if (!encrypt || block_len == 16) {
            memcpy(block, input + i, block_len);
        } else {
            // 加密且是最后一个不完整块
            memcpy(block, input + i, block_len);
            block_len = pkcs7_pad(block, block_len, 16);
        }
        
        sm4_block_crypt(block, output + out_len, rk, encrypt);
        out_len += 16;
    }
    
    // 解密时需要去除填充
    if (!encrypt) {
        out_len = pkcs7_unpad(output, out_len);
        if (out_len < 0) {
            fprintf(stderr, "Invalid padding\n");
            return -1;
        }
    }
    
    return out_len;
}

// 测试函数
void test_sm4() {
    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t plain[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t cipher[16], decrypted[16];
    
    printf("=== SM4 Test ===\n");
    printf("Key: ");
    for (int i = 0; i < 16; i++) printf("%02x", key[i]);
    printf("\nPlain: ");
    for (int i = 0; i < 16; i++) printf("%02x", plain[i]);
    
    // 加密测试
    sm4_crypt(plain, 16, cipher, key, 1);
    printf("\nCipher: ");
    for (int i = 0; i < 16; i++) printf("%02x", cipher[i]);
    
    // 解密测试
    sm4_crypt(cipher, 16, decrypted, key, 0);
    printf("\nDecrypted: ");
    for (int i = 0; i < 16; i++) printf("%02x", decrypted[i]);
    
    // 验证结果
    printf("\nResult: %s\n", memcmp(plain, decrypted, 16) == 0 ? "PASS" : "FAIL");
}

int main() {
    test_sm4();
    return 0;
}
