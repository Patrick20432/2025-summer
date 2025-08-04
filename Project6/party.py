# party.py
from crypto_utils import CryptoUtils

class Party1:
    def __init__(self, private_set):
        self.V = private_set
        self.crypto = CryptoUtils()
        self.k1 = self.crypto.random_scalar()
        self.paillier_pk = None
        self.intersection_indices = []

    def set_public_key(self, pk):
        self.paillier_pk = pk

    def round1(self):
        return [self.crypto.point_multiply(
                    self.crypto.hash_to_point(v), self.k1) for v in self.V]

    def round3(self, Z, enc_pairs):
        z_set = {self.crypto.point_to_bytes(p) for p in Z}
        intersection_cts = []
        for idx, (point_k2, enc_val) in enumerate(enc_pairs):
            combined_point = self.crypto.point_multiply(point_k2, self.k1)
            if self.crypto.point_to_bytes(combined_point) in z_set:
                self.intersection_indices.append(idx)
                intersection_cts.append(enc_val)

        if intersection_cts:
            sum_ct = self.crypto.paillier_add(intersection_cts, self.paillier_pk.n2)
            refreshed_ct = self.crypto.paillier_refresh(self.paillier_pk, sum_ct)
            return refreshed_ct, self.intersection_indices
        return None, []

class Party2:
    def __init__(self, private_set_with_values):
        self.W = private_set_with_values
        self.crypto = CryptoUtils()
        self.k2 = self.crypto.random_scalar()
        self.paillier_pk, self.paillier_sk = self.crypto.paillier_keygen()

    def get_public_key(self):
        return self.paillier_pk

    def round2(self, hashed_from_p1):
        Z = [self.crypto.point_multiply(p, self.k2) for p in hashed_from_p1]
        enc_pairs = []
        for w, t in self.W:
            point_k2 = self.crypto.point_multiply(
                self.crypto.hash_to_point(w), self.k2)
            enc_t = self.crypto.paillier_encrypt(self.paillier_pk, t)
            enc_pairs.append((point_k2, enc_t))
        return Z, enc_pairs

    def decrypt_result(self, ciphertext):
        if ciphertext is None:
            return 0
        return self.crypto.paillier_decrypt(self.paillier_sk, ciphertext)
