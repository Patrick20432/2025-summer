# crypto_utils.py
import hashlib
import random
from ecdsa import SECP256k1
from paillier import generate_paillier_keypair

class CryptoUtils:
    def __init__(self):
        self.curve = SECP256k1
        self.order = self.curve.order

    def random_scalar(self):
        return random.randrange(1, self.order)

    def hash_to_point(self, identifier_str, salt=b"common-seed"):
        h = hashlib.sha256(salt + identifier_str.encode()).digest()
        scalar = int.from_bytes(h, "big") % self.order
        return self.curve.generator * scalar

    def point_multiply(self, point, scalar):
        return point * (scalar % self.order)

    def point_to_bytes(self, point):
        return point.x().to_bytes(32, "big") + point.y().to_bytes(32, "big")

    # Paillier
    def paillier_keygen(self):
        return generate_paillier_keypair()

    def paillier_encrypt(self, pk, plaintext):
        return pk.encrypt(plaintext)

    def paillier_decrypt(self, sk, ciphertext):
        return sk.decrypt(ciphertext)

    def paillier_add(self, ciphertexts, n2):
        total = 1
        for ct in ciphertexts:
            total = (total * ct) % n2
        return total

    def paillier_refresh(self, pk, ciphertext):
        return pk.rerandomize(ciphertext)
