# paillier.py
import random
import math

def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

def invmod(a, m):
    """求模逆"""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y

class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n
        self.n2 = n * n
        self.g = g

    def encrypt(self, m):
        """Paillier 加密: Enc(m) = g^m * r^n mod n^2"""
        r = random.randrange(1, self.n)
        while math.gcd(r, self.n) != 1:
            r = random.randrange(1, self.n)
        return pow(self.g, m, self.n2) * pow(r, self.n, self.n2) % self.n2

    def rerandomize(self, c):
        """刷新密文：c * Enc(0)"""
        r = random.randrange(1, self.n)
        while math.gcd(r, self.n) != 1:
            r = random.randrange(1, self.n)
        return (c * pow(r, self.n, self.n2)) % self.n2

class PaillierPrivateKey:
    def __init__(self, public_key, lam, mu):
        self.public_key = public_key
        self.lam = lam
        self.mu = mu

    def decrypt(self, c):
        u = pow(c, self.lam, self.public_key.n2)
        l = (u - 1) // self.public_key.n
        return (l * self.mu) % self.public_key.n

def generate_paillier_keypair(bits=512):
    """生成 Paillier 密钥对"""
    p = q = 0
    while p == q:
        p = random_prime(bits // 2)
        q = random_prime(bits // 2)
    n = p * q
    g = n + 1
    lam = lcm(p - 1, q - 1)
    mu = invmod((pow(g, lam, n * n) - 1) // n, n)
    pk = PaillierPublicKey(n, g)
    sk = PaillierPrivateKey(pk, lam, mu)
    return pk, sk

def random_prime(bits):
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # 保证是奇数且最高位为1
        if is_prime(num):
            return num

def is_prime(n, k=5):
    """Miller-Rabin 素性测试"""
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
