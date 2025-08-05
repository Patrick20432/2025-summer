import numpy as np
from utils import bytes_to_words, words_to_bytes
from sm4_basic import SBOX, FK, CK

def rotl(x, n):
    """循环左移"""
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def sm4_sbox_np(a):
    """NumPy S-box 查表"""
    # a 是 uint32 数组
    res = ((np.take(SBOX, (a >> 24) & 0xFF).astype(np.uint32) << 24) |
           (np.take(SBOX, (a >> 16) & 0xFF).astype(np.uint32) << 16) |
           (np.take(SBOX, (a >> 8) & 0xFF).astype(np.uint32) << 8) |
           (np.take(SBOX, a & 0xFF).astype(np.uint32)))
    return res

def T_np(x):
    """加密时 T 变换（NumPy）"""
    b = sm4_sbox_np(x)
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)

def T_key_np(x):
    """密钥扩展时 T' 变换（NumPy）"""
    b = sm4_sbox_np(x)
    return b ^ rotl(b, 13) ^ rotl(b, 23)

def key_schedule_np(key):
    """NumPy 向量化密钥扩展"""
    MK = np.array(bytes_to_words(key), dtype=np.uint32)
    K = MK ^ np.array(FK, dtype=np.uint32)
    rk = []
    for i in range(32):
        t = T_key_np(K[1] ^ K[2] ^ K[3] ^ np.uint32(CK[i]))
        K = np.append(K, K[0] ^ t)
        rk.append(K[-1])
        K = K[1:]  # 保持长度4
    return np.array(rk, dtype=np.uint32)

def sm4_encrypt_blocks_np(key, plaintext_blocks):
    """
    NumPy 批量加密
    plaintext_blocks: bytes 列表，每个元素是16字节
    返回: bytes 列表
    """
    n = len(plaintext_blocks)
    rk = key_schedule_np(key)

    # 转成 uint32 矩阵 shape=(n,4)
    X = np.array([bytes_to_words(pt) for pt in plaintext_blocks], dtype=np.uint32)

    for i in range(32):
        tmp = T_np(X[:, 1] ^ X[:, 2] ^ X[:, 3] ^ rk[i])
        new_word = X[:, 0] ^ tmp
        # 左移一列
        X = np.column_stack((X[:, 1], X[:, 2], X[:, 3], new_word))

    # 反序
    X = X[:, ::-1]

    # 转回 bytes
    return [words_to_bytes(list(row)) for row in X]

if __name__ == "__main__":
    import time

    key = b"\x01" * 16
    plaintexts = [b"\x00" * 16 for _ in range(100000)]  # 10万块数据

    start = time.time()
    sm4_encrypt_blocks_np(key, plaintexts)
    print("NumPy 批量加密耗时:", time.time() - start, "秒")
