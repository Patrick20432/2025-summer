pragma circom 2.1.4;

// 引入 Circomlib 的 Poseidon 模板作为基础
// 注意: 尽管我们引入了，但我们在这里会自己实现 Poseidon2 的逻辑
include "../node_modules/circomlib/circuits/poseidon.circom"`;

// Poseidon2的线性层矩阵乘法
// M_PRIME 矩阵是为 t=3 设计的，值根据论文 Table 1 精简而来
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
        for (var j = 0; j < t; j++) {`
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
template Poseidon2Hasher() {
    // ---- 公开输入和隐私输入 ----
    signal private input preimage;  // 隐私输入：哈希原象 (即 x)
    signal public input hash;       // 公开输入：哈希值 (即 H)
    
    // ---- 算法参数 ----
    const t = 3; // 状态大小
    const d = 5; // S-box幂次
    
    // 轮数参数 R_F 和 R_P 需要根据论文 Table 1 确定
    // t=3, d=5, n=256 -> R_F=4, R_P=56
    const R_F = 4;
    const R_P = 56;

    // 声明状态信号数组
    signal state[t];
    state[0] <== preimage;
    state[1] <== 0;
    state[2] <== 0;

    // ---- Poseidon2 哈希函数逻辑 ----

    // 1. 初始线性层
    component linear_start = Poseidon2Linear(t);
    for (var i = 0; i < t; i++) {
        linear_start.in[i] <== state[i];
    }
    for (var i = 0; i < t; i++) {
        state[i] <== linear_start.out[i];
    }
    
    // 2. 全轮 S-box 和线性层组件
    // 定义组件数组，避免命名冲突
    component sbox_mid[R_F/2][t];
    component linear_mid[R_F/2];
    for (var r = 0; r < R_F / 2; r++) {
        // S-box
        for (var i = 0; i < t; i++) {
            sbox_mid[r][i] = Poseidon2Sbox(d);
            sbox_mid[r][i].in <== state[i];
            state[i] <== sbox_mid[r][i].out;
        }

        // Linear Layer
        linear_mid[r] = Poseidon2Linear(t);
        for (var i = 0; i < t; i++) {
            linear_mid[r].in[i] <== state[i];
        }
        for (var i = 0; i < t; i++) {
            state[i] <== linear_mid[r].out[i];
        }
    }

    // 3. 部分轮 S-box 和线性层组件
    // 定义组件数组，避免命名冲突
    component sbox_partial[R_P];
    component linear_partial[R_P];
    for (var r = 0; r < R_P; r++) {
        // S-box 只作用于第一个元素
        sbox_partial[r] = Poseidon2Sbox(d);
        sbox_partial[r].in <== state[0];
        state[0] <== sbox_partial[r].out;

        // Linear Layer
        linear_partial[r] = Poseidon2Linear(t);
        for (var i = 0; i < t; i++) {
            linear_partial[r].in[i] <== state[i];
        }
        for (var i = 0; i < t; i++) {
            state[i] <== linear_partial[r].out[i];
        }
    }

    // 4. 结尾全轮 S-box 和线性层组件
    // 定义组件数组，避免命名冲突
    component sbox_end[R_F/2][t];
    component linear_end[R_F/2];
    for (var r = 0; r < R_F / 2; r++) {
        // S-box
        for (var i = 0; i < t; i++) {
            sbox_end[r][i] = Poseidon2Sbox(d);
            sbox_end[r][i].in <== state[i];
            state[i] <== sbox_end[r][i].out;
        }

        // Linear Layer
        linear_end[r] = Poseidon2Linear(t);
        for (var i = 0; i < t; i++) {
            linear_end[r].in[i] <== state[i];
        }
        for (var i = 0; i < t; i++) {
            state[i] <== linear_end[r].out[i];
        }
    }

    // 5. 将最终状态的第一个元素（哈希结果）与公开输入进行比对
    hash === state[0];
}

// 定义主组件，这是我们将要编译的电路
component main = Poseidon2Hasher();