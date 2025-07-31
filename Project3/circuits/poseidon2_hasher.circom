pragma circom 2.1.4;

// 引入 Circomlib 的 Poseidon 模板作为基础
// 我们将对其进行修改，以适应 Poseidon2 的线性层
include "../node_modules/circomlib/circuits/poseidon.circom";

// 为了 Poseidon2，我们需要一个不同的线性层矩阵。
// 在 Poseidon2 论文中，这个矩阵 M 是一个高效的 M_hat * M_prime 结构。
// 在这里，我们将简化为直接定义一个矩阵。
// 实际生产环境中，我们会使用更复杂的矩阵生成逻辑。
//
// 注意: 这个矩阵 M_PRIME 是为了 Poseidon2 特性而设计的。
// 实际矩阵值需要根据论文和参数 t=3 精确计算得到。
// 这里我们使用一个简化的例子，实际值需要你根据论文 Table 1 精确查找。
// 论文 Table 1 的矩阵是在 GF(p) 上定义的，这里我们使用硬编码的常量。
// 由于circomlib没有直接提供poseidon2的矩阵，我们需要手动创建。
// 这是一个简化的 M_PRIME 矩阵示例，用于演示目的
template Poseidon2Linear(t) {
    signal input in[t];
    signal output out[t];

    var M_PRIME[3][3] = [
        [5, 7, 1],
        [1, 5, 7],
        [7, 1, 5]
    ];
    
    // M_PRIME 矩阵乘法
    for (var i = 0; i < t; i++) {
        out[i] <-- 0;
        for (var j = 0; j < t; j++) {
            out[i] += in[j] * M_PRIME[i][j];
        }
    }
}

// Poseidon2的S-box函数
template Poseidon2Sbox(d) {
    signal input in;
    signal output out;

    out <== in**d;
}

// 核心电路模板
// (n, t, d)=(256, 3, 5)
// 这里我们定义一个模板，它接受输入和输出
template Poseidon2Hasher() {
    // ---- 公开输入和隐私输入 ----
    // `private` 关键字表示这是一个隐私输入，证明者知道但验证者不知道。
    // `public` 关键字表示这是一个公开输入，证明者和验证者都知道。
    signal private input preimage;  // 隐私输入：哈希原象 (即 x)
    signal public input hash;       // 公开输入：哈希值 (即 H)
    
    // ---- 算法参数 ----
    const t = 3; // 状态大小
    const d = 5; // S-box幂次
    
    // 这里我们仅考虑单个 block 的输入，因此输入状态为 t-1 个零 + 1 个原象。
    // 实际中，输入可能需要 padding 和 absorption 步骤。
    // 为了简化，我们将输入直接放入状态的第一位
    signal state[t];
    state[0] <== preimage;
    state[1] <== 0;
    state[2] <== 0;

    // ---- Poseidon2 哈希函数逻辑 ----
    // 这里我们模拟 Poseidon2 的轮函数，包括全轮和部分轮
    // 轮数参数 R_F 和 R_P 需要根据论文 Table 1 确定
    // t=3, d=5, n=256 -> R_F=4, R_P=56
    const R_F = 4;
    const R_P = 56;

    // 1. 初始线性层 (MDS 矩阵乘法)
    // Poseidon2的MDS矩阵与Poseidon不同。这里我们使用简化模板
    // 实际需要一个更复杂的 Poseidon2MDS 模板
    component linear_start = Poseidon2Linear(t);
    for (var i = 0; i < t; i++) {
        linear_start.in[i] <== state[i];
    }
    for (var i = 0; i < t; i++) {
        state[i] <== linear_start.out[i];
    }

    // 2. 全轮 (R_F/2 轮)
    for (var r = 0; r < R_F / 2; r++) {
        // AddRoundConstant (需要从论文中获取常量)
        // 为了简化，我们假设常量为 0
        // for (var i = 0; i < t; i++) { state[i] += round_constants[r][i]; }

        // S-box
        for (var i = 0; i < t; i++) {
            component sbox = Poseidon2Sbox(d);
            sbox.in <== state[i];
            state[i] <== sbox.out;
        }

        // Linear Layer
        component linear_mid = Poseidon2Linear(t);
        for (var i = 0; i < t; i++) {
            linear_mid.in[i] <== state[i];
        }
        for (var i = 0; i < t; i++) {
            state[i] <== linear_mid.out[i];
        }
    }

    // 3. 部分轮 (R_P 轮)
    for (var r = 0; r < R_P; r++) {
        // AddRoundConstant
        // for (var i = 0; i < t; i++) { state[i] += round_constants[R_F/2+r][i]; }

        // S-box 只作用于第一个元素
        component sbox = Poseidon2Sbox(d);
        sbox.in <== state[0];
        state[0] <== sbox.out;

        // Linear Layer
        component linear_partial = Poseidon2Linear(t);
        for (var i = 0; i < t; i++) {
            linear_partial.in[i] <== state[i];
        }
        for (var i = 0; i < t; i++) {
            state[i] <== linear_partial.out[i];
        }
    }

    // 4. 全轮 (R_F/2 轮)
    for (var r = 0; r < R_F / 2; r++) {
        // AddRoundConstant
        // for (var i = 0; i < t; i++) { state[i] += round_constants[R_F/2+R_P+r][i]; }

        // S-box
        for (var i = 0; i < t; i++) {
            component sbox = Poseidon2Sbox(d);
            sbox.in <== state[i];
            state[i] <== sbox.out;
        }

        // Linear Layer
        component linear_end = Poseidon2Linear(t);
        for (var i = 0; i < t; i++) {
            linear_end.in[i] <== state[i];
        }
        for (var i = 0; i < t; i++) {
            state[i] <== linear_end.out[i];
        }
    }

    // 5. 将最终状态的第一个元素（哈希结果）与公开输入进行比对
    hash === state[0];
}

// 定义主组件，这是我们将要编译的电路
component main = Poseidon2Hasher();