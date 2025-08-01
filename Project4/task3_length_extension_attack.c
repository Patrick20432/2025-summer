#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm3.h"

// 辅助函数：将字节数组转换为十六进制字符串
void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_str) {
    for (size_t i = 0; i < len; ++i) {
        sprintf(hex_str + i * 2, "%02x", bytes[i]);
    }
}

// 辅助函数：将十六进制字符串转换为字节数组
void hex_to_bytes(const char *hex_str, uint8_t *bytes) {
    for (size_t i = 0; i < strlen(hex_str) / 2; ++i) {
        sscanf(hex_str + i * 2, "%2hhx", &bytes[i]);
    }
}

int main() {
    printf("--- 任务3: 长度扩展攻击验证 ---\n\n");
    
    // 1. 模拟一个我们不知道的密钥和消息
    const char *secret_key = "my_secret_key";
    const char *message = "message";
    
    // 2. 假设我们只知道哈希值和原始消息总长度（密钥长度+消息长度）
    size_t key_len = strlen(secret_key); // 攻击者需要猜或通过其他方式获取
    size_t msg_len = strlen(message);
    size_t total_len = key_len + msg_len;

    // 拼接原始消息 (key || message)
    uint8_t *original_data = (uint8_t *)malloc(total_len);
    memcpy(original_data, secret_key, key_len);
    memcpy(original_data + key_len, message, msg_len);
    
    uint8_t known_hash[SM3_HASH_SIZE];
    sm3(original_data, total_len, known_hash);
    
    char known_hash_hex[SM3_HASH_SIZE * 2 + 1];
    bytes_to_hex(known_hash, SM3_HASH_SIZE, known_hash_hex);

    printf("原始消息: \"%s\"\n", message);
    printf("原始哈希值 H(key || message): %s\n", known_hash_hex);
    printf("--- 攻击者开始攻击 ---\n\n");

    // 3. 攻击者构造新的消息
    const char *new_message = "new_data";

    // 4. 计算原始消息的填充长度
    // SM3填充规则: 原始总长度 + '1' + '0's + 64位长度 = 512的倍数
    // 填充后的总长度 l 满足 l % 512 == 448
    uint64_t total_bits = (uint64_t)total_len * 8;
    size_t padding_len_bytes = SM3_BLOCK_SIZE - (total_len % SM3_BLOCK_SIZE) - 9;
    if ((total_len % SM3_BLOCK_SIZE) >= 56) { // 如果空间不足以放填充和长度
        padding_len_bytes += SM3_BLOCK_SIZE;
    }
    
    // 5. 伪造新的哈希值
    // 使用已知的哈希值作为新的初始状态
    sm3_context attack_ctx;
    // 将已知的哈希值转换为32位字格式，作为新的初始状态
    for (int i = 0; i < 8; ++i) {
        attack_ctx.state[i] = ((uint32_t)known_hash[i*4]) << 24 | ((uint32_t)known_hash[i*4+1]) << 16 |
                              ((uint32_t)known_hash[i*4+2]) << 8 | ((uint32_t)known_hash[i*4+3]);
    }
    
    // 攻击者需要计算出原始消息+填充后的总长度（以比特为单位）
    uint64_t padded_total_bits = total_bits + 8 + (uint64_t)padding_len_bytes * 8 + 64;
    attack_ctx.total_bits = padded_total_bits;

    // 用新的消息来更新哈希值
    sm3_update(&attack_ctx, (const uint8_t*)new_message, strlen(new_message));
    
    uint8_t forged_hash[SM3_HASH_SIZE];
    sm3_final(&attack_ctx, forged_hash);
    
    char forged_hash_hex[SM3_HASH_SIZE * 2 + 1];
    bytes_to_hex(forged_hash, SM3_HASH_SIZE, forged_hash_hex);
    
    printf("攻击者构造的新消息: \"%s\"\n", new_message);
    printf("伪造的哈希值: %s\n\n", forged_hash_hex);

    // 6. 验证攻击是否成功
    // 真实计算 H(key || message || padding || new_message)
    size_t real_padded_len = total_len + padding_len_bytes + 9;
    size_t real_extended_len = real_padded_len + strlen(new_message);
    uint8_t *real_extended_data = (uint8_t *)malloc(real_extended_len);
    
    // 复制原始数据
    memcpy(real_extended_data, original_data, total_len);
    
    // 复制填充 (10000000)
    real_extended_data[total_len] = 0x80;
    memset(real_extended_data + total_len + 1, 0, padding_len_bytes);
    
    // 复制原始消息长度（64位）
    uint64_t total_bits_be = __builtin_bswap64(total_bits);
    memcpy(real_extended_data + total_len + 1 + padding_len_bytes, &total_bits_be, 8);
    
    // 复制新的消息
    memcpy(real_extended_data + real_padded_len, new_message, strlen(new_message));

    uint8_t real_hash[SM3_HASH_SIZE];
    sm3(real_extended_data, real_extended_len, real_hash);

    char real_hash_hex[SM3_HASH_SIZE * 2 + 1];
    bytes_to_hex(real_hash, SM3_HASH_SIZE, real_hash_hex);

    printf("--- 验证攻击是否成功 ---\n");
    printf("真实哈希值 H(key || message || padding || new_message):\n%s\n", real_hash_hex);

    if (memcmp(forged_hash, real_hash, SM3_HASH_SIZE) == 0) {
        printf("攻击成功！伪造的哈希值与真实哈希值匹配。\n");
    } else {
        printf("攻击失败！伪造的哈希值与真实哈希值不匹配。\n");
    }

    free(original_data);
    free(real_extended_data);
    
    return 0;
}