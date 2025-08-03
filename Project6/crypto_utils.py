import hashlib
from phe import paillier
from ecdsa import SigningKey, SECP256k1
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class CryptoUtils:
    def __init__(self):
        self.curve = SECP256k1
        self.order = self.curve.order

        self.private_key = SigningKey.generate(curve=self.curve)
        self.public_key = self.private_key.get_verifying_key()

    def hash_to_point(self, identifier_str):
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'psi-hash-to-curve',
            backend=default_backend()
        )
        derived = kdf.derive(identifier_str.encode())
        private_value = int.from_bytes(derived, 'big') % self.order
        point = self.public_key.pubkey.point * private_value
        print(f"Hashed identifier '{identifier_str}' to point: ({point.x()}, {point.y()})")
        return point

    def point_multiply(self, point, scalar_bytes):
        scalar = int.from_bytes(scalar_bytes, 'big') % self.order
        result = point * scalar
        print(f"Point multiply: ({point.x()}, {point.y()}) * {scalar} = ({result.x()}, {result.y()})")
        return result

    def point_to_bytes(self, point):
        print(f"Serializing point: ({point.x()}, {point.y()})")
        return point.x().to_bytes(32, 'big') + point.y().to_bytes(32, 'big')

    def bytes_to_point(self, byte_str):
        x = int.from_bytes(byte_str[:32], 'big')
        y = int.from_bytes(byte_str[32:], 'big')
        point = self.curve.curve.point(x, y)
        print(f"Deserializing point: ({x}, {y})")
        return point

    @staticmethod
    def paillier_keygen():
        return paillier.generate_paillier_keypair()

    @staticmethod
    def paillier_encrypt(pk, plaintext):
        return pk.encrypt(plaintext)

    @staticmethod
    def paillier_decrypt(sk, ciphertext):
        return sk.decrypt(ciphertext)

    @staticmethod
    def paillier_add(ciphertexts):
        if not ciphertexts:
            return None
        total = ciphertexts[0]
        for ct in ciphertexts[1:]:
            total += ct
        return total

    @staticmethod
    def paillier_refresh(ciphertext):
        return ciphertext.rerandomize()