# sm2/sm2_core.py
import hashlib
import secrets
from typing import Tuple


class SM2Curve:
    """SM2椭圆曲线参数及基本运算"""

    def __init__(self):
        # SM2推荐参数
        self.p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
        self.a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
        self.b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
        self.n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
        self.Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
        self.Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2

    def point_add(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点加法"""
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        if P[0] == Q[0] and (P[1] != Q[1] or P[1] == 0):
            return (0, 0)

        if P == Q:
            lam = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], -1, self.p) % self.p
        else:
            lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, self.p) % self.p

        x3 = (lam * lam - P[0] - Q[0]) % self.p
        y3 = (lam * (P[0] - x3) - P[1]) % self.p
        return (x3, y3)

    def scalar_mult(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线标量乘法（double-and-add算法）"""
        result = (0, 0)  # 无穷远点
        addend = P

        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result


class SM2:
    """SM2数字签名算法实现"""

    def __init__(self):
        self.curve = SM2Curve()
        self.hash_func = hashlib.sha256  # 实际应用应使用SM3

    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        """生成SM2密钥对"""
        private_key = secrets.randbelow(self.curve.n - 1) + 1
        public_key = self.curve.scalar_mult(private_key, (self.curve.Gx, self.curve.Gy))
        return private_key, public_key

    def sign(self, private_key: int, message: str, user_id: str = "default") -> Tuple[int, int]:
        """SM2签名"""
        # 简化版ZA计算
        ZA = hashlib.sha256(user_id.encode()).digest()
        e = int.from_bytes(hashlib.sha256(ZA + message.encode()).digest(), 'big') % self.curve.n

        while True:
            k = secrets.randbelow(self.curve.n - 1) + 1
            x1, y1 = self.curve.scalar_mult(k, (self.curve.Gx, self.curve.Gy))
            r = (e + x1) % self.curve.n
            if r == 0 or r + k == self.curve.n:
                continue

            s = (pow(1 + private_key, -1, self.curve.n) * (k - r * private_key)) % self.curve.n
            if s != 0:
                return (r, s)

    def verify(self, public_key: Tuple[int, int], message: str, signature: Tuple[int, int],
               user_id: str = "default") -> bool:
        """SM2验证"""
        r, s = signature
        if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
            return False

        ZA = hashlib.sha256(user_id.encode()).digest()
        e = int.from_bytes(hashlib.sha256(ZA + message.encode()).digest(), 'big') % self.curve.n

        t = (r + s) % self.curve.n
        if t == 0:
            return False

        x1, y1 = self.curve.point_add(
            self.curve.scalar_mult(s, (self.curve.Gx, self.curve.Gy)),
            self.curve.scalar_mult(t, public_key)
        )

        R = (e + x1) % self.curve.n
        return R == r

    # 添加到 sm2_core.py 的 SM2 类中
    def compute_ZA(self, user_id: str, pub_key: tuple) -> bytes:
        """计算SM2签名所需的ZA"""
        entl = len(user_id).to_bytes(2, 'big')
        a_bytes = self.int_to_bytes(self.curve.a)
        b_bytes = self.int_to_bytes(self.curve.b)
        gx_bytes = self.int_to_bytes(self.curve.Gx)
        gy_bytes = self.int_to_bytes(self.curve.Gy)
        x_bytes = self.int_to_bytes(pub_key[0])
        y_bytes = self.int_to_bytes(pub_key[1])
        return hashlib.sha256(entl + user_id.encode() + a_bytes + b_bytes +
                              gx_bytes + gy_bytes + x_bytes + y_bytes).digest()

    # 同时添加辅助方法
    def int_to_bytes(self, x: int) -> bytes:
        """整数转换为字节"""
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')

# 在sm2_core.py文件末尾添加：
if __name__ == "__main__":
    print("=== SM2实现测试 ===")

    sm2 = SM2()

    # 1. 密钥生成测试
    private_key, public_key = sm2.generate_keypair()
    print(f"私钥: {private_key}")
    print(f"公钥: ({public_key[0]}, {public_key[1]})")

    # 2. 签名验证测试
    message = "测试消息123"
    signature = sm2.sign(private_key, message)
    print(f"签名: (r={signature[0]}, s={signature[1]})")

    # 3. 验证测试
    is_valid = sm2.verify(public_key, message, signature)
    print(f"验证结果: {'成功' if is_valid else '失败'}")

    # 4. 错误签名测试
    fake_signature = (signature[0] + 1, signature[1])  # 篡改r值
    is_valid = sm2.verify(public_key, message, fake_signature)
    print(f"伪造签名验证: {'异常成功' if is_valid else '正常失败'}")