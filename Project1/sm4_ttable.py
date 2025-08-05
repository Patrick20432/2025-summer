# sm4_ttable.py
from utils import bytes_to_words, words_to_bytes
from sm4_basic import SBOX, FK, CK

def rotl(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

# 生成T表
TBL = [0] * 256
TBL_KEY = [0] * 256

for i in range(256):
    b = SBOX[i]
    w = (b << 24) | (b << 16) | (b << 8) | b
    TBL[i] = w ^ rotl(w, 2) ^ rotl(w, 10) ^ rotl(w, 18) ^ rotl(w, 24)
    TBL_KEY[i] = w ^ rotl(w, 13) ^ rotl(w, 23)

def T(x):
    return TBL[(x >> 24) & 0xFF] ^ \
           TBL[(x >> 16) & 0xFF] ^ \
           TBL[(x >> 8) & 0xFF] ^ \
           TBL[x & 0xFF]

def T_key(x):
    return TBL_KEY[(x >> 24) & 0xFF] ^ \
           TBL_KEY[(x >> 16) & 0xFF] ^ \
           TBL_KEY[(x >> 8) & 0xFF] ^ \
           TBL_KEY[x & 0xFF]

def key_schedule(key):
    MK = bytes_to_words(key)
    K = [MK[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        K.append(K[i] ^ T_key(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]))
        rk.append(K[i+4])
    return rk

def sm4_encrypt_block(key, plaintext):
    rk = key_schedule(key)
    X = bytes_to_words(plaintext)
    for i in range(32):
        X.append(X[i] ^ T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]))
    return words_to_bytes(X[35:31:-1])

def sm4_decrypt_block(key, ciphertext):
    rk = key_schedule(key)[::-1]
    X = bytes_to_words(ciphertext)
    for i in range(32):
        X.append(X[i] ^ T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]))
    return words_to_bytes(X[35:31:-1])

if __name__ == "__main__":
    import time
    key = b"\x01" * 16
    plaintext = b"\x00" * 16

    start = time.time()
    for _ in range(100000):
        sm4_encrypt_block(key, plaintext)
    print("T-table version:", time.time() - start, "seconds")
