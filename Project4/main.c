#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sm3.h"
#include "sm3_optimized.h"
#include "length_extension_attack.c" // 为了方便，直接include
#include "merkle_tree.h"

#define NUM_LEAVES 100000

// 辅助函数：将字节数组转换为十六进制字符串
void print_hash(const char* label, const uint8_t* hash) {
    char hex_str[SM3_HASH_SIZE * 2 + 1];
    for (int i = 0; i < SM3_HASH_SIZE; ++i) {
        sprintf(hex_str + i * 2, "%02x", hash[i]);
    }
    printf("%s: %s\n", label, hex_str);
}

int main() {
    // 1. SM3基本实现测试
    printf("--- 1. SM3 Basic Implementation Test ---\n");
    const char* message = "abc";
    uint8_t hash[SM3_HASH_SIZE];
    sm3((const uint8_t*)message, strlen(message), hash);
    print_hash("SM3(\"abc\")", hash);
    
    // 2. SM3优化实现测试
    printf("\n--- 2. SM3 Optimized Implementation Test ---\n");
    // 这里我们只展示使用优化版sm3_compress的哈希函数，性能测试需要更精细的计时
    sm3_context ctx_opt;
    sm3_init(&ctx_opt);
    sm3_update(&ctx_opt, (const uint8_t*)message, strlen(message));
    sm3_final(&ctx_opt, hash); // 这里应该调用优化版的sm3_compress
    print_hash("SM3_optimized(\"abc\")", hash);
    
    // 3. 长度扩展攻击验证
    printf("\n--- 3. Length Extension Attack Verification ---\n");
    length_extension_attack();
    
    // 4. Merkle树构建与证明
    printf("\n--- 4. Merkle Tree Construction and Proofs ---\n");
    
    // 准备叶子数据
    leaf_data_t *leaves = (leaf_data_t *)malloc(NUM_LEAVES * sizeof(leaf_data_t));
    for (int i = 0; i < NUM_LEAVES; ++i) {
        sprintf((char*)leaves[i].data, "data for leaf %d", i);
        leaves[i].len = strlen((char*)leaves[i].data);
    }
    
    // 构建Merkle树
    // 估算树存储空间
    uint32_t tree_size = 2 * NUM_LEAVES * SM3_HASH_SIZE; 
    uint8_t *tree_hashes = (uint8_t *)malloc(tree_size);
    uint8_t root_hash[SM3_HASH_SIZE];

    build_merkle_tree(leaves, NUM_LEAVES, root_hash, tree_hashes);
    print_hash("Merkle Root", root_hash);
    
    // 存在性证明
    uint32_t target_leaf_index = 55555;
    merkle_proof_t inclusion_proof;
    generate_inclusion_proof(target_leaf_index, NUM_LEAVES, tree_hashes, &inclusion_proof);
    
    uint8_t target_leaf_hash[SM3_HASH_SIZE];
    sm3(leaves[target_leaf_index].data, leaves[target_leaf_index].len, target_leaf_hash);
    
    bool is_present = verify_inclusion_proof(target_leaf_hash, root_hash, &inclusion_proof);
    printf("Leaf %u is present: %s\n", target_leaf_index, is_present ? "true" : "false");

    // 不存在性证明 (这里是简化的实现)
    uint8_t non_existent_hash[SM3_HASH_SIZE] = {0}; // 假设这个哈希值不存在
    
    merkle_proof_t exclusion_proof1, exclusion_proof2;
    uint32_t index1, index2;
    uint8_t leaf_hash1[SM3_HASH_SIZE];
    uint8_t leaf_hash2[SM3_HASH_SIZE];

    // 在实际中，我们会在这里找到两个相邻叶子节点
    // 为了演示，我们直接使用两个相邻叶子节点
    sm3(leaves[target_leaf_index-1].data, leaves[target_leaf_index-1].len, leaf_hash1);
    sm3(leaves[target_leaf_index+1].data, leaves[target_leaf_index+1].len, leaf_hash2);
    
    generate_exclusion_proof(non_existent_hash, NUM_LEAVES, tree_hashes, tree_hashes, &exclusion_proof1, &exclusion_proof2, &index1, &index2);

    bool is_not_present = verify_exclusion_proof(non_existent_hash, root_hash, &exclusion_proof1, &exclusion_proof2, leaf_hash1, leaf_hash2);
    printf("Non-existent hash is not present: %s\n", is_not_present ? "true" : "false");
    
    free(leaves);
    free(tree_hashes);

    return 0;
}