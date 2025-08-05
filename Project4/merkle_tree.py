import struct
import math
import random
import hashlib


# ========================
# Part 1: 基础版 SM3 实现
# ========================

IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

T_j = [0x79CC4519] * 16 + [0x7A879D8A] * 48

def _rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> (32 - n))

def _P0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)

def _P1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)

def _FFj(x, y, z, j):
    return (x ^ y ^ z) if j <= 15 else ((x & y) | (x & z) | (y & z))

def _GGj(x, y, z, j):
    return (x ^ y ^ z) if j <= 15 else ((x & y) | (~x & z))

def sm3_pad(msg: bytes):
    l = len(msg) * 8
    msg += b'\x80'
    msg += b'\x00' * ((56 - (len(msg) % 64)) % 64)
    msg += struct.pack(">Q", l)
    return msg

def sm3_msg_extend(B):
    W = list(struct.unpack(">16I", B))
    for j in range(16, 68):
        W.append(_P1(W[j-16] ^ W[j-9] ^ _rotl(W[j-3], 15)) ^ _rotl(W[j-13], 7) ^ W[j-6])
    W_ = [(W[j] ^ W[j+4]) & 0xFFFFFFFF for j in range(64)]
    return W, W_

def sm3_cf(V, B):
    A, B_, C, D, E, F, G, H = V
    W, W_ = sm3_msg_extend(B)
    for j in range(64):
        SS1 = _rotl((_rotl(A, 12) + E + _rotl(T_j[j], j % 32)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (_FFj(A, B_, C, j) + D + SS2 + W_[j]) & 0xFFFFFFFF
        TT2 = (_GGj(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = _rotl(B_, 9)
        B_ = A
        A = TT1
        H = G
        G = _rotl(F, 19)
        F = E
        E = _P0(TT2)
    return [(v ^ x) & 0xFFFFFFFF for v, x in zip(V, [A, B_, C, D, E, F, G, H])]

def sm3_hash(msg: bytes):
    msg = sm3_pad(msg)
    V = IV[:]
    for i in range(0, len(msg), 64):
        V = sm3_cf(V, msg[i:i+64])
    return ''.join(f'{x:08x}' for x in V)


# ========================
# Part 2: 优化版 SM3（Python 算法优化）
# ========================

def sm3_hash_fast(msg: bytes):
    """减少局部变量创建 & 避免不必要的列表"""
    msg = sm3_pad(msg)
    V = IV[:]
    for i in range(0, len(msg), 64):
        W = list(struct.unpack(">16I", msg[i:i+64]))
        for j in range(16, 68):
            p1 = W[j-16] ^ W[j-9] ^ _rotl(W[j-3], 15)
            p1 = p1 ^ _rotl(p1, 15) ^ _rotl(p1, 23)
            W.append((p1 ^ _rotl(W[j-13], 7) ^ W[j-6]) & 0xFFFFFFFF)
        W_ = [(W[j] ^ W[j+4]) & 0xFFFFFFFF for j in range(64)]
        A, B_, C, D, E, F, G, H = V
        for j in range(64):
            SS1 = _rotl((_rotl(A, 12) + E + _rotl(T_j[j], j % 32)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ _rotl(A, 12)
            TT1 = (_FFj(A, B_, C, j) + D + SS2 + W_[j]) & 0xFFFFFFFF
            TT2 = (_GGj(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D, C, B_, A = C, _rotl(B_, 9), A, TT1
            H, G, F, E = G, _rotl(F, 19), E, _P0(TT2)
        V = [(v ^ x) & 0xFFFFFFFF for v, x in zip(V, [A, B_, C, D, E, F, G, H])]
    return ''.join(f'{x:08x}' for x in V)


# ========================
# Part 3: 长度扩展攻击
# ========================

def sm3_len_ext_attack(orig_hash, orig_len, append_msg):
    """orig_hash: 已知的哈希 (hex)
       orig_len: 原消息长度 (字节)
       append_msg: 想追加的数据 (bytes)
    """
    # 还原中间状态
    state = [int(orig_hash[i:i+8], 16) for i in range(0, 64, 8)]

    # 构造 padding（针对原消息）
    glue_padding = sm3_pad(b'A' * orig_len)[orig_len:]

    # 计算新哈希
    new_msg_len = orig_len + len(glue_padding) + len(append_msg)
    append_padded = append_msg
    append_padded = sm3_pad(append_padded)
    V = state[:]
    for i in range(0, len(append_padded), 64):
        V = sm3_cf(V, append_padded[i:i+64])
    new_hash = ''.join(f'{x:08x}' for x in V)
    return new_hash, glue_padding


# ========================
# Part 4: Merkle Tree
# ========================

class MerkleTree:
    def __init__(self, leaves):
        self.leaves = [bytes.fromhex(sm3_hash(l)) for l in leaves]
        self.levels = []
        self.build_tree()

    def build_tree(self):
        level = self.leaves
        self.levels.append(level)
        while len(level) > 1:
            new_level = []
            for i in range(0, len(level), 2):
                if i+1 < len(level):
                    combined = level[i] + level[i+1]
                else:
                    combined = level[i] + level[i]
                new_level.append(bytes.fromhex(sm3_hash(combined)))
            level = new_level
            self.levels.append(level)

    def get_root(self):
        return self.levels[-1][0].hex()

    def get_proof(self, index):
        proof = []
        for level in self.levels[:-1]:
            sibling = index ^ 1
            if sibling < len(level):
                proof.append(level[sibling])
            index >>= 1
        return proof

    @staticmethod
    def verify_proof(leaf, proof, root, index):
        h = bytes.fromhex(sm3_hash(leaf))
        for p in proof:
            if index % 2 == 0:
                h = bytes.fromhex(sm3_hash(h + p))
            else:
                h = bytes.fromhex(sm3_hash(p + h))
            index >>= 1
        return h.hex() == root


# ========================
# 测试示例
# ========================
if __name__ == "__main__":

    msg = b"abc"

    # Part 4: Merkle Tree
    leaves = [f"leaf{i}".encode() for i in range(10**5)]
    mt = MerkleTree(leaves)
    root = mt.get_root()
    proof = mt.get_proof(1234)
    print("Merkle Root:", root)
    print("验证:", MerkleTree.verify_proof(b"leaf1234", proof, root, 1234))
