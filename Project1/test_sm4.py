import time
from sm4_basic import sm4_encrypt_block
from sm4_ttable import sm4_encrypt_block as sm4_ttable_enc
from sm4_numpy import sm4_encrypt_blocks_np
from sm4_gcm import sm4_gcm_encrypt

def test_basic(key, plaintexts):
    start = time.time()
    for pt in plaintexts:
        sm4_encrypt_block(key, pt)
    return time.time() - start

def test_ttable(key, plaintexts):
    start = time.time()
    for pt in plaintexts:
        sm4_ttable_enc(key, pt)
    return time.time() - start

def test_numpy(key, plaintexts):
    start = time.time()
    sm4_encrypt_blocks_np(key, plaintexts)
    return time.time() - start

def test_gcm(key, iv, plaintext, aad):
    start = time.time()
    sm4_gcm_encrypt(key, iv, plaintext, aad)
    return time.time() - start

if __name__ == "__main__":
    key = b"\x01" * 16
    iv = b"\x00" * 12
    aad = b"header-data"

    # 测试数据
    num_blocks = 100000  # 10万块（1.6MB）
    plaintext_blocks = [b"\x00" * 16 for _ in range(num_blocks)]
    plaintext_bytes = b"".join(plaintext_blocks)

    # 1. 基础版
    t1 = test_basic(key, plaintext_blocks)
    print(f"[Basic] {num_blocks} blocks: {t1:.4f} 秒, 速度: {num_blocks*16/t1/1024/1024:.2f} MB/s")

    # 2. T-table版
    t2 = test_ttable(key, plaintext_blocks)
    print(f"[T-table] {num_blocks} blocks: {t2:.4f} 秒, 速度: {num_blocks*16/t2/1024/1024:.2f} MB/s")

    # 3. NumPy批量版
    t3 = test_numpy(key, plaintext_blocks)
    print(f"[NumPy Batch] {num_blocks} blocks: {t3:.4f} 秒, 速度: {num_blocks*16/t3/1024/1024:.2f} MB/s")

    # 4. NumPy GCM模式
    t4 = test_gcm(key, iv, plaintext_bytes, aad)
    print(f"[GCM Mode] {len(plaintext_bytes)} bytes: {t4:.4f} 秒, 速度: {len(plaintext_bytes)/t4/1024/1024:.2f} MB/s")


   