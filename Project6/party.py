import random
import os
from crypto_utils import CryptoUtils

class Party1:
    def __init__(self, private_set):
        self.V = private_set
        self.crypto = CryptoUtils()
        self.k1 = os.urandom(32)
        self.paillier_pk = None
        self.intersection_indices = []

    def set_public_key(self, pk):
        self.paillier_pk = pk

    def round1(self):
        print("P1: Round 1 - Hashing and encrypting my set")
        encrypted_points = []
        for v in self.V:
            point = self.crypto.hash_to_point(v)
            encrypted_point = self.crypto.point_multiply(point, self.k1)
            encrypted_points.append(encrypted_point)
        # random.shuffle(encrypted_points)  # 暂时禁用随机化
        return encrypted_points

    def round3(self, Z_prime, encrypted_pairs):
        print("P1: Round 3 - Finding intersection")
        z_bytes_set = {self.crypto.point_to_bytes(p) for p in Z_prime}

        intersection_cts = []
        for idx, (point, ct) in enumerate(encrypted_pairs):
            combined_point = self.crypto.point_multiply(point, self.k1)
            combined_bytes = self.crypto.point_to_bytes(combined_point)
            if combined_bytes in z_bytes_set:
                self.intersection_indices.append(idx)
                intersection_cts.append(ct)

        print(f"P1: Found {len(self.intersection_indices)} items in intersection")
        if intersection_cts:
            sum_ct = self.crypto.paillier_add(intersection_cts)
            refreshed_ct = self.crypto.paillier_refresh(sum_ct)
            return refreshed_ct, self.intersection_indices
        return None, []

class Party2:
    def __init__(self, private_set_with_values):
        self.W = private_set_with_values
        self.crypto = CryptoUtils()
        self.k2 = os.urandom(32)
        self.paillier_pk, self.paillier_sk = self.crypto.paillier_keygen()

    def get_public_key(self):
        return self.paillier_pk

    def round2(self, encrypted_points_from_p1):
        print("P2: Round 2 - Processing both sets")
        Z_prime = [
            self.crypto.point_multiply(point, self.k2)
            for point in encrypted_points_from_p1
        ]
        # random.shuffle(Z_prime)  # 暂时禁用随机化

        encrypted_pairs = []
        for w, t in self.W:
            point = self.crypto.hash_to_point(w)
            encrypted_point = self.crypto.point_multiply(point, self.k2)
            encrypted_t = self.crypto.paillier_encrypt(self.paillier_pk, t)
            encrypted_pairs.append((encrypted_point, encrypted_t))
        # random.shuffle(encrypted_pairs)  # 暂时禁用随机化
        return Z_prime, encrypted_pairs

    def decrypt_result(self, ciphertext):
        if ciphertext is None:
            return 0
        return self.crypto.paillier_decrypt(self.paillier_sk, ciphertext)