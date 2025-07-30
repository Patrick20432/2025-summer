import sys
import binascii

# 使用官方标准S-Box (GB/T 32907-2016)
SM4_SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
]

# 修正后的FK值 (使用大端序表示)
FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

# 修正CK值 (完整32个)
CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
]


def rol(x, n, bits=32):
    n = n % bits
    return ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)

def tau(A):
    """非线性变换τ：应用S-Box到32位字的每个字节"""
    return ((SM4_SBOX[(A >> 24) & 0xFF] << 24) |
            (SM4_SBOX[(A >> 16) & 0xFF] << 16) |
            (SM4_SBOX[(A >> 8) & 0xFF] << 8) |
            (SM4_SBOX[A & 0xFF]))

def L(B):
    """加密线性变换：L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)"""
    return B ^ rol(B, 2) ^ rol(B, 10) ^ rol(B, 18) ^ rol(B, 24)

def L_prime(B):
    """密钥扩展线性变换：L'(B) = B ⊕ (B <<< 13) ⊕ (B <<< 23)"""
    return B ^ rol(B, 13) ^ rol(B, 23)

def T(A):
    """加密轮函数：T(·) = L(τ(·))"""
    return L(tau(A))

def T_prime(A):
    """密钥扩展函数：T'(·) = L'(τ(·))"""
    return L_prime(tau(A))

def generate_round_keys(master_key):
    """SM4密钥扩展算法"""
    # 128位主密钥分为4个32位字
    MK = [(master_key >> (96 - i * 32)) & 0xFFFFFFFF for i in range(4)]
    
    # 初始化和密钥异或固定参数
    K = [MK[i] ^ FK[i] for i in range(4)]
    
    # 生成32个轮密钥
    rk = [0] * 32
    for i in range(32):
        # 关键步骤：前4个密钥组合
        temp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]
        # 应用T'变换并与当前密钥异或
        k_next = K[i] ^ T_prime(temp)
        K.append(k_next)  # 存储为下一轮使用
        rk[i] = k_next
    
    return rk

def sm4_block_crypt(block, round_keys, encrypt=True):
    """SM4分组加密/解密核心函数"""
    # 将128位块拆分为4个32位字 (X0, X1, X2, X3)
    X = [(block >> (96 - i * 32)) & 0xFFFFFFFF for i in range(4)]
    
    # 32轮Feistel网络
    for r in range(32):
        # 选择轮密钥：加密顺序，解密逆序
        rk = round_keys[r] if encrypt else round_keys[31 - r]
        
        # 轮函数输入：X1 ⊕ X2 ⊕ X3 ⊕ rk
        input_val = X[1] ^ X[2] ^ X[3] ^ rk
        
        # 应用T变换
        t_val = T(input_val)
        
        # 计算新字：X0 ⊕ T(·)
        new_X = X[0] ^ t_val
        
        # 状态更新：向右移动字
        X = [X[1], X[2], X[3], new_X]
    
    # 最终反序输出：X3, X2, X1, X0 → 128位块
    return (X[3] << 96) | (X[2] << 64) | (X[1] << 32) | X[0]

# 辅助函数
def bytes_to_int(byte_array):
    return int.from_bytes(byte_array, 'big')

def int_to_bytes(integer, length):
    return integer.to_bytes(length, 'big')

def sm4_crypt(data, key, encrypt=True, padding='pkcs7'):
    """完整SM4加密/解密函数，支持多分组"""
    block_size = 16  # 128位块
    
    # 密钥验证
    if len(key) != block_size:
        raise ValueError(f"密钥长度必须是{block_size}字节")
    
    # 密钥扩展
    master_key = bytes_to_int(key)
    round_keys = generate_round_keys(master_key)
    
    # 加密填充处理
    if encrypt and padding == 'pkcs7':
        pad_len = block_size - (len(data) % block_size)
        data += bytes([pad_len] * pad_len)
    # 解密数据长度验证
    elif not encrypt and len(data) % block_size != 0:
        raise ValueError("密文长度必须是块大小的倍数")
    
    # 处理数据块
    result = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        block_int = bytes_to_int(block)
        cipher_int = sm4_block_crypt(block_int, round_keys, encrypt)
        result.extend(int_to_bytes(cipher_int, block_size))
    
    # 解密填充移除
    if not encrypt and padding == 'pkcs7':
        pad_len = result[-1]
        # 验证填充有效性
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("无效填充长度")
        if result[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("填充验证失败")
        result = result[:-pad_len]
    
    return bytes(result)

if __name__ == "__main__":
    # 验证标准测试向量
    print("=== 标准测试向量验证 ===")
    test_key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    test_plain = bytes.fromhex("0123456789abcdeffedcba9876543210")
    expected_cipher = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
    
    # 直接调用块加密
    master_key_int = int.from_bytes(test_key, "big")
    block_int = int.from_bytes(test_plain, "big")
    round_keys = generate_round_keys(master_key_int)
    cipher_int = sm4_block_crypt(block_int, round_keys, True)
    cipher_bytes = cipher_int.to_bytes(16, "big")
    
    print(f"密钥: {test_key.hex()}")
    print(f"明文: {test_plain.hex()}")
    print(f"预期: {expected_cipher.hex()}")
    print(f"实际: {cipher_bytes.hex()}")
    print(f"匹配: {cipher_bytes == expected_cipher}")
    
    # 验证解密
    decrypted_int = sm4_block_crypt(cipher_int, round_keys, False)
    decrypted_bytes = decrypted_int.to_bytes(16, "big")
    print(f"解密: {decrypted_bytes.hex()}")
    print(f"还原: {decrypted_bytes == test_plain}")