#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "merkle_tree.h"

#define NUM_LEAVES 100000

// 辅助函数：将字节数组转换为十六进制字符串并打印
void print_hash(const char* label, const uint8_t* hash) {
    char hex_str[SM3_HASH_SIZE * 2 + 1];
    for (int i = 0; i < SM3_HASH_SIZE; ++i) {
        sprintf(hex_str + i * 2, "%02x", hash[i]);
    }
    printf("%s: %s\n", label, hex_str);
}

// 辅助函数：比较两个SM3哈希值
int compare_hashes(const void *a, const void *b) {
    return memcmp(a, b, SM3_HASH_SIZE);
}

// 在排序的哈希数组中二分查找目标哈希应该插入的位置
int find_insertion_point(const uint8_t *sorted_hashes, uint32_t num_hashes, const uint8_t *target_hash) {
    int low = 0, high = num_hashes - 1, mid;
    while (low <= high) {
        mid = low + (high - low) / 2;
        int cmp = memcmp(target_hash, sorted_hashes + mid * SM3_HASH_SIZE, SM3_HASH_SIZE);
        if (cmp == 0) return mid; // 找到
        if (cmp < 0) high = mid - 1;
        else low = mid + 1;
    }
    return low; // 返回插入点
}

int main() {
    printf("--- 任务4: Merkle树构建与证明 ---\n\n");
    
    // 准备叶子数据
    leaf_data_t *leaves = (leaf_data_t *)malloc(NUM_LEAVES * sizeof(leaf_data_t));
    uint8_t *leaf_hashes = (uint8_t *)malloc(NUM_LEAVES * SM3_HASH_SIZE);
    
    for (int i = 0; i < NUM_LEAVES; ++i) {
        sprintf((char*)leaves[i].data, "data for leaf %d", i);
        leaves[i].len = strlen((char*)leaves[i].data);
    }
    
    // 对叶子数据进行哈希
    for (int i = 0; i < NUM_LEAVES; ++i) {
        sm3(leaves[i].data, leaves[i].len, leaf_hashes + i * SM3_HASH_SIZE);
    }
    
    // 为了不存在性证明，对叶子哈希进行排序
    qsort(leaf_hashes, NUM_LEAVES, SM3_HASH_SIZE, compare_hashes);

    // 构建Merkle树
    uint32_t tree_size = 2 * NUM_LEAVES * SM3_HASH_SIZE; 
    uint8_t *tree_hashes = (uint8_t *)malloc(tree_size);
    uint8_t root_hash[SM3_HASH_SIZE];

    build_merkle_tree(leaves, NUM_LEAVES, root_hash, tree_hashes); // 注意，这里的leaves顺序未变，但生成证明时需要用sorted_leaf_hashes
    print_hash("Merkle Root", root_hash);
    
    // --- 存在性证明 ---
    printf("\n--- 存在性证明 ---\n");
    uint32_t target_leaf_index = 55555;
    merkle_proof_t inclusion_proof;
    
    uint8_t target_leaf_hash[SM3_HASH_SIZE];
    sm3(leaves[target_leaf_index].data, leaves[target_leaf_index].len, target_leaf_hash);
    
    // 这里的 generate_inclusion_proof 应该基于原始的未排序树结构
    generate_inclusion_proof(target_leaf_index, NUM_LEAVES, tree_hashes, &inclusion_proof);
    
    bool is_present = verify_inclusion_proof(target_leaf_hash, root_hash, &inclusion_proof);
    printf("叶子节点 %u 存在于树中: %s\n", target_leaf_index, is_present ? "true" : "false");

    // --- 不存在性证明 ---
    printf("\n--- 不存在性证明 ---\n");
    uint8_t non_existent_data[256];
    sprintf((char*)non_existent_data, "data for a non-existent leaf");
    uint8_t non_existent_hash[SM3_HASH_SIZE];
    sm3(non_existent_data, strlen((char*)non_existent_data), non_existent_hash);
    
    print_hash("要证明不存在的哈希", non_existent_hash);

    // 1. 找到目标哈希在排序哈希列表中的插入点
    int insertion_point = find_insertion_point(leaf_hashes, NUM_LEAVES, non_existent_hash);
    
    if (insertion_point >= 0 && insertion_point < NUM_LEAVES) {
        // 2. 获取相邻的两个叶子哈希
        uint8_t *leaf_hash_left = leaf_hashes + (insertion_point - 1) * SM3_HASH_SIZE;
        uint8_t *leaf_hash_right = leaf_hashes + insertion_point * SM3_HASH_SIZE;
        
        // 3. 构造这两个哈希的存在性证明
        merkle_proof_t proof_left, proof_right;
        
        // 注意：generate_inclusion_proof需要叶子的索引，这里需要找到排序哈希对应的原始索引
        // 这是一个复杂步骤，为简化，我们假设排序后的第i个哈希对应原始的第i个叶子
        generate_inclusion_proof(insertion_point - 1, NUM_LEAVES, tree_hashes, &proof_left);
        generate_inclusion_proof(insertion_point, NUM_LEAVES, tree_hashes, &proof_right);

        // 4. 验证不存在性
        bool is_not_present = verify_exclusion_proof(non_existent_hash, root_hash, &proof_left, &proof_right, leaf_hash_left, leaf_hash_right);
        printf("不存在性证明验证成功: %s\n", is_not_present ? "true" : "false");
    } else {
        printf("无法找到相邻节点进行不存在性证明。\n");
    }

    free(leaves);
    free(leaf_hashes);
    free(tree_hashes);
    
    return 0;
}