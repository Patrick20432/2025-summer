# -*- coding: utf-8 -*-
# sm2/sm2_forgery.py
from sm2_core import SM2, SM2Curve
import secrets
import hashlib


def demonstrate_malleability():
    """展示 SM2 签名的延展性（s → -s mod n）"""
    sm2 = SM2()
    d, P = sm2.generate_keypair()
    msg = "伪造测试消息"

    # 正常签名
    r, s = sm2.sign(d, msg)
    print(f"原始签名: r={r}")
    print(f"原始签名: s={s}")

    # 延展性签名
    s_malleated = (-s) % sm2.curve.n
    print(f"延展性签名: r={r}")
    print(f"延展性签名: s={s_malleated}")

    # 验证两者
    valid1 = sm2.verify(P, msg, (r, s))
    valid2 = sm2.verify(P, msg, (r, s_malleated))
    print(f"原始签名验证结果: {'成功' if valid1 else '失败'}")
    print(f"延展性签名验证结果: {'成功' if valid2 else '失败'}")


def simulate_nakamoto_forgery():
    """教学演示：伪造中本聪签名（仅概念）"""
    # 1. 用 SM2 生成一对“假·中本聪”密钥
    sm2 = SM2()
    d_fake, P_fake = sm2.generate_keypair()
    fake_tx = "中本聪向攻击者转移 100 BTC"

    # 2. 用假私钥签名
    r, s = sm2.sign(d_fake, fake_tx)
    print(f"\n伪造交易内容: {fake_tx}")
    print(f"伪造签名 (SM2): r={r}")
    print(f"伪造签名 (SM2): s={s}")
    print("伪造签名验证结果:", "成功" if sm2.verify(P_fake, fake_tx, (r, s)) else "失败")

    # 3. 提示：真正比特币用的是 ECDSA/secp256k1，而非 SM2
    print("""
注意：
- 真实比特币使用 ECDSA 在 secp256k1 曲线上，**不是 SM2**。
- 本演示仅在 SM2 场景下展示“伪造”概念，无法直接攻击比特币。
- 真实场景伪造需要：
  1. 中本聪真实的 secp256k1 公钥  
  2. 该密钥存在 k 重用等漏洞
""")


if __name__ == "__main__":
    print("===== SM2 签名延展性演示 =====")
    demonstrate_malleability()

    print("\n===== 伪造中本聪签名演示 =====")
    simulate_nakamoto_forgery()