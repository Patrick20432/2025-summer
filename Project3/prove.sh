#!/bin/bash

# --- Groth16 证明生成流程 ---

echo "1. 生成 Witness"
# snarkjs wc：生成 witness
# 第一个参数是编译后的 .wasm 文件
# 第二个参数是输入 .json 文件
# 第三个参数是输出的 witness 文件
snarkjs wc poseidon2_hasher.wasm input.json witness.wtns

echo "2. Groth16 零知识证明设置"
# snarkjs groth16 setup：创建用于生成证明的密钥
# 第一个参数是 R1CS 文件
# 第二个参数是输出的 .zkey 文件 (存储证明密钥)
# 第三个参数是权力之塔 (Phase 2 Ceremony) 过程的随机数
snarkjs groth16 setup poseidon2_hasher.r1cs poseidon2_hasher_0.zkey -s

echo "3. Groth16 证明密钥更新"
# 为了生产环境的安全，需要多次更新
snarkjs zkey contribute poseidon2_hasher_0.zkey poseidon2_hasher_1.zkey --name="First Contribution" -e="random text"

echo "4. 生成证明"
# snarkjs groth16 prove：生成零知识证明
# 第一个参数是 .zkey 文件
# 第二个参数是 witness 文件
# 第三个参数是输出的证明文件 (.json)
# 第四个参数是输出的公开输入文件 (.json)
snarkjs groth16 prove poseidon2_hasher_1.zkey witness.wtns proof.json public.json

echo "5. 验证证明"
# snarkjs groth16 verify：验证零知识证明
# 第一个参数是 .zkey 文件
# 第二个参数是公开输入文件
# 第三个参数是证明文件
snarkjs groth16 verify poseidon2_hasher_1.zkey public.json proof.json

echo "证明生成和验证完成！"