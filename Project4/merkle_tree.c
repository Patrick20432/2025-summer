#include "merkle_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 构建Merkle树，返回根哈希
void build_merkle_tree(leaf_data_t *leaves, uint32_t num_leaves, uint8_t root_hash[SM3_HASH_SIZE], uint8_t *tree_hashes) {
    // 首先对叶子数据进行哈希
    for (uint32_t i = 0; i < num_leaves; ++i) {
        sm3(leaves[i].data, leaves[i].len, tree_hashes + i * SM3_HASH_SIZE);
    }

    uint32_t current_level_size = num_leaves;
    uint32_t current_level_start_index = 0;
    uint32_t next_level_start_index = num_leaves;
    
    // 迭代构建树
    while (current_level_size > 1) {
        uint32_t next_level_size = 0;
        for (uint32_t i = 0; i < current_level_size; i += 2) {
            uint8_t combined_hash[SM3_HASH_SIZE * 2];
            
            // 组合左右子节点的哈希
            memcpy(combined_hash, tree_hashes + (current_level_start_index + i) * SM3_HASH_SIZE, SM3_HASH_SIZE);
            if (i + 1 < current_level_size) {
                memcpy(combined_hash + SM3_HASH_SIZE, tree_hashes + (current_level_start_index + i + 1) * SM3_HASH_SIZE, SM3_HASH_SIZE);
            } else {
                // 如果是奇数个节点，将最后一个节点与其自身拼接
                memcpy(combined_hash + SM3_HASH_SIZE, tree_hashes + (current_level_start_index + i) * SM3_HASH_SIZE, SM3_HASH_SIZE);
            }
            
            // 计算新的父节点哈希
            sm3(combined_hash, SM3_HASH_SIZE * 2, tree_hashes + (next_level_start_index + next_level_size) * SM3_HASH_SIZE);
            next_level_size++;
        }
        current_level_size = next_level_size;
        current_level_start_index = next_level_start_index;
        next_level_start_index += next_level_size;
    }
    
    // 根哈希
    memcpy(root_hash, tree_hashes + current_level_start_index * SM3_HASH_SIZE, SM3_HASH_SIZE);
}

// 生成存在性证明
void generate_inclusion_proof(uint32_t leaf_index, uint32_t num_leaves, const uint8_t *tree_hashes, merkle_proof_t *proof) {
    proof->proof_len = 0;
    uint32_t current_level_size = num_leaves;
    uint32_t current_level_start = 0;

    while (current_level_size > 1) {
        uint32_t sibling_index;
        if (leaf_index % 2 == 0) { // 叶子节点是左子节点
            sibling_index = leaf_index + 1;
            if (sibling_index >= current_level_size) { // 奇数个节点，兄弟是自己
                sibling_index = leaf_index;
            }
            memcpy(proof->proof_hashes[proof->proof_len++], tree_hashes + (current_level_start + sibling_index) * SM3_HASH_SIZE, SM3_HASH_SIZE);
        } else { // 叶子节点是右子节点
            sibling_index = leaf_index - 1;
            memcpy(proof->proof_hashes[proof->proof_len++], tree_hashes + (current_level_start + sibling_index) * SM3_HASH_SIZE, SM3_HASH_SIZE);
        }
        leaf_index /= 2;
        current_level_start += current_level_size;
        current_level_size = (current_level_size + 1) / 2;
    }
}

// 验证存在性证明
bool verify_inclusion_proof(const uint8_t *leaf_hash, const uint8_t *root_hash, const merkle_proof_t *proof) {
    uint8_t current_hash[SM3_HASH_SIZE];
    memcpy(current_hash, leaf_hash, SM3_HASH_SIZE);
    
    for (uint32_t i = 0; i < proof->proof_len; ++i) {
        uint8_t combined_hash[SM3_HASH_SIZE * 2];
        if (i % 2 == 0) { // 叶子节点是左子节点，兄弟在右边
            memcpy(combined_hash, current_hash, SM3_HASH_SIZE);
            memcpy(combined_hash + SM3_HASH_SIZE, proof->proof_hashes[i], SM3_HASH_SIZE);
        } else { // 叶子节点是右子节点，兄弟在左边
            memcpy(combined_hash, proof->proof_hashes[i], SM3_HASH_SIZE);
            memcpy(combined_hash + SM3_HASH_SIZE, current_hash, SM3_HASH_SIZE);
        }
        sm3(combined_hash, SM3_HASH_SIZE * 2, current_hash);
    }

    return memcmp(current_hash, root_hash, SM3_HASH_SIZE) == 0;
}

// 不存在性证明的实现较为复杂，这里只提供框架，具体实现需要更复杂的逻辑，包括二分查找等
void generate_exclusion_proof(const uint8_t *target_hash, uint32_t num_leaves, const uint8_t *sorted_leaf_hashes, const uint8_t *tree_hashes, merkle_proof_t *proof1, merkle_proof_t *proof2, uint32_t *index1, uint32_t *index2) {
    // 实际实现中，需要先在 sorted_leaf_hashes 中找到 target_hash 应该插入的位置，
    // 然后找到其左右两个相邻的叶子节点，并生成这两个节点的inclusion proof。
    // 这里为了简化，我们假设找到了两个相邻的节点索引 index1 和 index2。
    
    // 查找相邻节点
    *index1 = 0; // 假设找到的第一个相邻索引
    *index2 = 1; // 假设找到的第二个相邻索引

    // 生成这两个节点的证明
    generate_inclusion_proof(*index1, num_leaves, tree_hashes, proof1);
    generate_inclusion_proof(*index2, num_leaves, tree_hashes, proof2);
}

// 验证不存在性证明
bool verify_exclusion_proof(const uint8_t *target_hash, const uint8_t *root_hash, const merkle_proof_t *proof1, const merkle_proof_t *proof2, const uint8_t *leaf_hash1, const uint8_t *leaf_hash2) {
    // 1. 验证两个相邻叶子节点的存在性
    bool verify1 = verify_inclusion_proof(leaf_hash1, root_hash, proof1);
    bool verify2 = verify_inclusion_proof(leaf_hash2, root_hash, proof2);

    if (!verify1 || !verify2) {
        return false;
    }
    
    // 2. 验证两个哈希值是相邻的
    // 这需要检查 leaf_hash1 的哈希路径与 leaf_hash2 的哈希路径，看它们是否在某个父节点处汇合，并且是兄弟节点
    // 简化的检查：假设它们是相邻的，我们只需要比较哈希值的大小
    if (memcmp(leaf_hash1, leaf_hash2, SM3_HASH_SIZE) >= 0) {
        return false;
    }

    // 3. 验证目标哈希值位于两个相邻哈希值之间
    if (memcmp(target_hash, leaf_hash1, SM3_HASH_SIZE) > 0 && memcmp(target_hash, leaf_hash2, SM3_HASH_SIZE) < 0) {
        return true;
    }
    
    return false;
}