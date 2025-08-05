import numpy as np
from sm4_numpy import sm4_encrypt_blocks_np
from utils import bytes_to_words, words_to_bytes

def int_to_bytes(n, length):
    return n.to_bytes(length, byteorder="big")

def bytes_to_int(b):
    return int.from_bytes(b, byteorder="big")

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def gf_mul(x, y):
    """GF(2^128) 乘法（NumPy版，GCM用）"""
    R = 0xE1000000000000000000000000000000
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z

def ghash(H, data):
    """GHASH 认证"""
    y = 0
    for block in data:
        y ^= bytes_to_int(block)
        y = gf_mul(y, H)
    return y

def inc32(counter_block):
    """增加计数器（低32位）"""
    counter = bytearray(counter_block)
    val = int.from_bytes(counter[12:], "big") + 1
    counter[12:] = (val & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(counter)

def sm4_gcm_encrypt(key, iv, plaintext, aad=b""):
    """
    SM4-GCM 加密（NumPy 批量优化）
    key: 16字节
    iv: 12字节（推荐）
    plaintext: bytes
    aad: 附加认证数据
    """
    # 1. 计算H = E_K(0^128)
    H = bytes_to_int(sm4_encrypt_blocks_np(key, [b"\x00" * 16])[0])

    # 2. 计算初始计数器 J0
    if len(iv) == 12:
        J0 = iv + b"\x00\x00\x00\x01"
    else:
        # 非12字节IV时需要GHASH计算
        len_block = int_to_bytes(0, 8) + int_to_bytes(len(iv) * 8, 8)
        J0 = int_to_bytes(ghash(H, iv + len_block), 16)

    # 3. 生成CTR序列
    blocks_needed = (len(plaintext) + 15) // 16
    counter_blocks = [J0]
    for _ in range(blocks_needed):
        counter_blocks.append(inc32(counter_blocks[-1]))
    counter_blocks = counter_blocks[1:]  # 去掉J0本身

    # 4. 批量加密CTR块
    keystream_blocks = sm4_encrypt_blocks_np(key, counter_blocks)

    # 5. XOR得到密文
    ciphertext_blocks = []
    for i in range(blocks_needed):
        pt_block = plaintext[i*16:(i+1)*16]
        ks_block = keystream_blocks[i]
        if len(pt_block) < 16:
            ks_block = ks_block[:len(pt_block)]
        ciphertext_blocks.append(xor_bytes(pt_block, ks_block))
    ciphertext = b"".join(ciphertext_blocks)

    # 6. 计算Tag
    u = (16 - (len(ciphertext) % 16)) % 16
    v = (16 - (len(aad) % 16)) % 16
    auth_data = aad + b"\x00" * v + ciphertext + b"\x00" * u
    len_block = int_to_bytes(len(aad) * 8, 8) + int_to_bytes(len(ciphertext) * 8, 8)
    S = ghash(H, [auth_data[i:i+16] for i in range(0, len(auth_data), 16)] + [len_block])
    tag = xor_bytes(int_to_bytes(S, 16), sm4_encrypt_blocks_np(key, [J0])[0])

    return ciphertext, tag

if __name__ == "__main__":
    import time
    key = b"\x01" * 16
    iv = b"\x00" * 12
    plaintext = b"hello world sm4 gcm test" * 10000  # 大批量测试
    aad = b"header-data"

    start = time.time()
    ciphertext, tag = sm4_gcm_encrypt(key, iv, plaintext, aad)
    end = time.time()

    print("Ciphertext (hex):", ciphertext[:32].hex(), "...")
    print("Tag:", tag.hex())
    print("Time:", end - start, "秒")
