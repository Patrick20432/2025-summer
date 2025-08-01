#include <stdint.h>
#include <string.h>
#include <stdio.h>

// SM3的初始哈希值IV
static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

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

// 循环左移宏
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3的非线性函数
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// SM3的置换函数
#define P0(x) ((x) ^ ROTL32(x, 9) ^ ROTL32(x, 17))
#define P1(x) ((x) ^ ROTL32(x, 15) ^ ROTL32(x, 23))

// SM3的常数Tj
#define T0_15 0x79CC4519
#define T16_63 0x7A879D8A

// 大端转换函数（用于将uint32_t转换为大端格式的字节数组）
static void be32_to_bytes(uint32_t val, uint8_t *bytes) {
    bytes[0] = (val >> 24) & 0xFF;
    bytes[1] = (val >> 16) & 0xFF;
    bytes[2] = (val >> 8) & 0xFF;
    bytes[3] = val & 0xFF;
}

// 消息扩展
static void sm3_message_expansion(const uint32_t *B, uint32_t *W, uint32_t *W_prime) {
    int i;
    for (i = 0; i < 16; ++i) {
        W[i] = B[i];
    }
    for (i = 16; i < 68; ++i) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL32(W[i - 3], 15)) ^ ROTL32(W[i - 13], 7) ^ W[i - 6];
    }
    for (i = 0; i < 64; ++i) {
        W_prime[i] = W[i] ^ W[i + 4];
    }
}

// 压缩函数
static void sm3_compress(uint32_t *state, const uint8_t *block) {
    uint32_t W[68], W_prime[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    uint32_t Tj;
    int i;

    // 将512比特分组转换为16个32位字（大端格式）
    uint32_t B_words[16];
    for (i = 0; i < 16; ++i) {
        B_words[i] = ((uint32_t)block[i * 4]) << 24 | ((uint32_t)block[i * 4 + 1]) << 16 |
                     ((uint32_t)block[i * 4 + 2]) << 8 | ((uint32_t)block[i * 4 + 3]);
    }

    // 消息扩展
    sm3_message_expansion(B_words, W, W_prime);

    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    for (i = 0; i < 64; ++i) {
        Tj = (i >= 0 && i <= 15) ? T0_15 : T16_63;

        SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(Tj, i), 7);
        SS2 = SS1 ^ ROTL32(A, 12);

        TT1 = (i >= 0 && i <= 15) ? FF0(A, B, C) + D + SS2 + W_prime[i] : FF1(A, B, C) + D + SS2 + W_prime[i];
        TT2 = (i >= 0 && i <= 15) ? GG0(E, F, G) + H + SS1 + W[i] : GG1(E, F, G) + H + SS1 + W[i];

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    // 更新哈希值
    state[0] ^= A;
    state[1] ^= B;
    state[2] ^= C;
    state[3] ^= D;
    state[4] ^= E;
    state[5] ^= F;
    state[6] ^= G;
    state[7] ^= H;
}

// 初始化SM3上下文
void sm3_init(sm3_context *ctx) {
    memcpy(ctx->state, IV, sizeof(IV));
    ctx->total_bits = 0;
    ctx->buffer_len = 0;
}

// 更新SM3哈希值，处理输入数据
void sm3_update(sm3_context *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    
    // 如果缓冲区中有数据，先填满缓冲区
    if (ctx->buffer_len > 0) {
        uint32_t fill_len = SM3_BLOCK_SIZE - ctx->buffer_len;
        if (len < fill_len) {
            memcpy(ctx->buffer + ctx->buffer_len, data, len);
            ctx->buffer_len += len;
            ctx->total_bits += len * 8;
            return;
        }
        memcpy(ctx->buffer + ctx->buffer_len, data, fill_len);
        sm3_compress(ctx->state, ctx->buffer);
        ctx->total_bits += fill_len * 8;
        ctx->buffer_len = 0;
        i += fill_len;
    }

    // 处理完整的512比特分组
    while (i + SM3_BLOCK_SIZE <= len) {
        sm3_compress(ctx->state, data + i);
        ctx->total_bits += SM3_BLOCK_SIZE * 8;
        i += SM3_BLOCK_SIZE;
    }

    // 将剩余数据放入缓冲区
    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
        ctx->buffer_len = len - i;
        ctx->total_bits += (len - i) * 8;
    }
}

// 结束SM3哈希计算，进行填充和最终压缩
void sm3_final(sm3_context *ctx, uint8_t hash[SM3_HASH_SIZE]) {
    uint64_t total_bits = ctx->total_bits;
    
    // 填充: 添加'1'
    ctx->buffer[ctx->buffer_len++] = 0x80;

    // 如果当前分组无法容纳64位长度信息，则需要添加一个全零分组
    if (ctx->buffer_len > SM3_BLOCK_SIZE - 8) {
        memset(ctx->buffer + ctx->buffer_len, 0, SM3_BLOCK_SIZE - ctx->buffer_len);
        sm3_compress(ctx->state, ctx->buffer);
        ctx->buffer_len = 0;
    }

    // 填充'0'
    memset(ctx->buffer + ctx->buffer_len, 0, SM3_BLOCK_SIZE - 8 - ctx->buffer_len);

    // 添加64位原始消息长度
    uint8_t len_bytes[8];
    len_bytes[0] = (total_bits >> 56) & 0xFF;
    len_bytes[1] = (total_bits >> 48) & 0xFF;
    len_bytes[2] = (total_bits >> 40) & 0xFF;
    len_bytes[3] = (total_bits >> 32) & 0xFF;
    len_bytes[4] = (total_bits >> 24) & 0xFF;
    len_bytes[5] = (total_bits >> 16) & 0xFF;
    len_bytes[6] = (total_bits >> 8) & 0xFF;
    len_bytes[7] = total_bits & 0xFF;
    memcpy(ctx->buffer + SM3_BLOCK_SIZE - 8, len_bytes, 8);

    // 最后一个分组的压缩
    sm3_compress(ctx->state, ctx->buffer);

    // 将最终状态转换为大端格式的哈希值
    for (int i = 0; i < 8; ++i) {
        be32_to_bytes(ctx->state[i], hash + i * 4);
    }
}

// 一次性计算SM3哈希值
void sm3(const uint8_t *data, size_t len, uint8_t hash[SM3_HASH_SIZE]) {
    sm3_context ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, hash);
}

// 辅助函数：将字节数组转换为十六进制字符串并打印
void print_hash(const char* label, const uint8_t* hash) {
    char hex_str[SM3_HASH_SIZE * 2 + 1];
    for (int i = 0; i < SM3_HASH_SIZE; ++i) {
        sprintf(hex_str + i * 2, "%02x", hash[i]);
    }
    printf("%s: %s\n", label, hex_str);
}

// 主函数，程序从这里开始执行
int main() {
    printf("--- 任务1: SM3基本实现 ---\n");
    const char* message = "abc";
    uint8_t hash[SM3_HASH_SIZE];

    sm3((const uint8_t*)message, strlen(message), hash);
    
    print_hash("SM3(\"abc\")", hash);

    return 0;
}