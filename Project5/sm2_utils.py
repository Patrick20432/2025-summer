# sm2/sm2_utils.py
import hashlib

def int_to_bytes(x: int) -> bytes:
    """整数转换为字节"""
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def bytes_to_int(b: bytes) -> int:
    """字节转换为整数"""
    return int.from_bytes(b, 'big')

def compute_za(user_id: str, pub_key: tuple, curve_params: dict) -> bytes:
    """计算SM2签名所需的ZA"""
    # 简化实现，实际应包含更多参数
    entl = len(user_id).to_bytes(2, 'big')
    return hashlib.sha256(entl + user_id.encode() +
                         int_to_bytes(curve_params['a']) +
                         int_to_bytes(curve_params['b']) +
                         int_to_bytes(curve_params['Gx']) +
                         int_to_bytes(curve_params['Gy']) +
                         int_to_bytes(pub_key[0]) +
                         int_to_bytes(pub_key[1])).digest()

import hashlib
from sm2_core import SM2       # 复用 SM2.int_to_bytes 等

def compute_ZA(sm2: SM2, user_id: str, pub_key: tuple) -> bytes:
    """国密 GM/T 0003.2 标准 ZA 计算"""
    curve = sm2.curve
    entl = len(user_id).to_bytes(2, 'big')
    a = sm2.int_to_bytes(curve.a)
    b = sm2.int_to_bytes(curve.b)
    gx = sm2.int_to_bytes(curve.Gx)
    gy = sm2.int_to_bytes(curve.Gy)
    xA = sm2.int_to_bytes(pub_key[0])
    yA = sm2.int_to_bytes(pub_key[1])
    return hashlib.sha256(
        entl + user_id.encode() + a + b + gx + gy + xA + yA
    ).digest()


def compute_sm2_e(sm2: SM2, user_id: str, pub_key: tuple, msg: bytes) -> int:
    """返回 SM2 签名真正用到的 e = sm3( ZA || msg )"""
    ZA = compute_ZA(sm2, user_id, pub_key)
    e_hash = hashlib.sha256(ZA + msg).digest()   # 这里用 SHA256 简化，可替换成 SM3
    return int.from_bytes(e_hash, 'big')