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
# 测试示例
# ========================
if __name__ == "__main__":
    # Part 1: 基础 SM3
    msg = b"abc"
    print("SM3 基础实现:", sm3_hash(msg))


