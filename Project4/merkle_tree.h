#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <stdint.h>
#include <stdbool.h>
#include "sm3.h"

// Merkle树的叶子节点数据类型
typedef struct {
    uint8_t data[256]; // 假设数据长度为256字节
    uint32_t len;
} leaf_data_t;

// Merkle树证明结构体
typedef struct {
    uint8_t proof_hashes[20][SM3_HASH_SIZE]; // 路径上的兄弟哈希值，假设树高不超过20
    uint32_t proof_len;
} merkle_proof_t;

// 构建Merkle树，返回根哈希
void build_merkle_tree(leaf_data_t *leaves, uint32_t num_leaves, uint8_t root_hash[SM3_HASH_SIZE], uint8_t *tree_hashes);

// 生成存在性证明
void generate_inclusion_proof(uint32_t leaf_index, uint32_t num_leaves, const uint8_t *tree_hashes, merkle_proof_t *proof);

// 验证存在性证明
bool verify_inclusion_proof(const uint8_t *leaf_hash, const uint8_t *root_hash, const merkle_proof_t *proof);

// 生成不存在性证明
void generate_exclusion_proof(const uint8_t *target_hash, uint32_t num_leaves, const uint8_t *sorted_leaf_hashes, const uint8_t *tree_hashes, merkle_proof_t *proof1, merkle_proof_t *proof2, uint32_t *index1, uint32_t *index2);

// 验证不存在性证明
bool verify_exclusion_proof(const uint8_t *target_hash, const uint8_t *root_hash, const merkle_proof_t *proof1, const merkle_proof_t *proof2, const uint8_t *leaf_hash1, const uint8_t *leaf_hash2);

#endif // MERKLE_TREE_H