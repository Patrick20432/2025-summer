_#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <string.h>

// SM3哈希值长度（256比特）
#define SM3_HASH_SIZE 32
// SM3分组长度（512比特）
#define SM3_BLOCK_SIZE 64

// SM3上下文结构体，用于保存哈希计算的中间状态
typedef struct {
    uint32_t state[8]; // 当前的哈希值状态 (A, B, C, D, E, F, G, H)
    uint64_t total_bits; // 已经处理的总比特数
    uint8_t buffer[SM3_BLOCK_SIZE]; // 待处理的分组数据缓冲区
    uint32_t buffer_len; // 缓冲区中数据的长度
} sm3_context;

// 初始化SM3上下文
void sm3_init(sm3_context *ctx);

// 更新SM3哈希值，处理输入数据
void sm3_update(sm3_context *ctx, const uint8_t *data, size_t len);

// 结束SM3哈希计算，进行填充和最终压缩
void sm3_final(sm3_context *ctx, uint8_t hash[SM3_HASH_SIZE]);

// 一次性计算SM3哈希值
void sm3(const uint8_t *data, size_t len, uint8_t hash[SM3_HASH_SIZE]);

#endif // SM3_H