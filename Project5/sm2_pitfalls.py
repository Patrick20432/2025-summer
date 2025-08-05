# sm2_pitfalls.py
from sm2_core import SM2, SM2Curve
from sm2_utils import compute_sm2_e
import secrets
import hashlib


def print_debug(title, *values):
    """打印调试信息"""
    print(f"\n[DEBUG] {title}")
    for i, val in enumerate(values, 1):
        print(f"  {i}. {val}")


def demonstrate_k_reuse():
    """k 重用攻击：一个 k 签两条不同消息"""
    sm2 = SM2()
    dA, PA = sm2.generate_keypair()
    dB, PB = sm2.generate_keypair()

    user_id = "alice_and_bob"
    msg1 = "重要消息1"
    msg2 = "重要消息2"

    # 正常签名消息1
    r1, s1 = sm2.sign(dA, msg1, user_id)

    # 反推 k
    e1 = compute_sm2_e(sm2, user_id, PA, msg1.encode())
    k = (s1 * (1 + dA) + r1 * dA) % sm2.curve.n

    # 使用相同 k 给消息2 签名
    e2 = compute_sm2_e(sm2, user_id, PA, msg2.encode())
    x1, _ = sm2.curve.scalar_mult(k, (sm2.curve.Gx, sm2.curve.Gy))
    r2 = (e2 + x1) % sm2.curve.n
    s2 = (pow(1 + dB, -1, sm2.curve.n) * (k - r2 * dB)) % sm2.curve.n

    # 恢复私钥
    recovered_dA = (k - s1) * pow(r1 + s1, -1, sm2.curve.n) % sm2.curve.n
    recovered_dB = (k - s2) * pow(r2 + s2, -1, sm2.curve.n) % sm2.curve.n

    print("k重用攻击结果:")
    print(f"原始dA: {dA}, 恢复dA: {recovered_dA}, {'成功' if dA == recovered_dA else '失败'}")
    print(f"原始dB: {dB}, 恢复dB: {recovered_dB}, {'成功' if dB == recovered_dB else '失败'}")


def demonstrate_same_d_k():
    sm2 = SM2()
    d, P = sm2.generate_keypair()
    msg = "相同消息"
    user_id = "test_user"

    # 1. 计算真正会被两条签名用到的 e（必须完全一致）
    e = compute_sm2_e(sm2, user_id, P, msg.encode())

    # 2. 随机 k
    k = secrets.randbelow(sm2.curve.n - 1) + 1
    x1, _ = sm2.curve.scalar_mult(k, (sm2.curve.Gx, sm2.curve.Gy))

    # 3. ECDSA 签名（标准公式）
    r_ecdsa = x1 % sm2.curve.n
    s_ecdsa = (pow(k, -1, sm2.curve.n) * (e + r_ecdsa * d)) % sm2.curve.n

    # 4. SM2 签名（标准公式）
    r_sm2 = (e + x1) % sm2.curve.n
    s_sm2 = (pow(1 + d, -1, sm2.curve.n) * (k - r_sm2 * d)) % sm2.curve.n

    # 5. 解方程
    #   ECDSA: s_ecdsa = (e + r_ecdsa·d)/k
    #   SM2  : s_sm2   = (k – r_sm2·d)/(1+d)
    # 消去 k 得：
    numerator   = (s_ecdsa * s_sm2 - e) % sm2.curve.n
    denominator = (r_ecdsa * s_sm2 - r_sm2 * s_ecdsa + s_ecdsa * s_sm2) % sm2.curve.n

    if denominator == 0:
        print("分母为 0，无法恢复")
        return
    recovered_d = numerator * pow(denominator, -1, sm2.curve.n) % sm2.curve.n

    print("\n相同d和k攻击结果:")
    print(f"原始d: {d}")
    print(f"恢复d: {recovered_d}")
    print("成功" if d == recovered_d else "失败")

if __name__ == "__main__":
    print("===== k重用攻击演示 =====")
    demonstrate_k_reuse()

    print("\n===== 相同d和k攻击演示 =====")
    demonstrate_same_d_k()