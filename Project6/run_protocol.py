# run_protocol.py
import random
from party import Party1, Party2

def simulate_protocol():
    print("=== DDH Private Intersection-Sum Protocol ===")

    common_users = [f"user_{i}" for i in range(5)]
    p1_data = common_users + [f"unique_{i}" for i in range(3)]
    p2_data = [(u, random.randint(10, 100)) for u in common_users] + \
              [(f"other_{i}", random.randint(10, 100)) for i in range(2)]

    random.shuffle(p1_data)
    random.shuffle(p2_data)

    print(f"P1 set size: {len(p1_data)}")
    print(f"P2 set size: {len(p2_data)}")
    print(f"Expected intersection size: {len(common_users)}")

    p1 = Party1(p1_data)
    p2 = Party2(p2_data)

    p1.set_public_key(p2.get_public_key())

    # Round 1
    hashed_from_p1 = p1.round1()

    # Round 2
    Z, enc_pairs = p2.round2(hashed_from_p1)

    # Round 3
    sum_ct, indices = p1.round3(Z, enc_pairs)

    # Output
    result_sum = p2.decrypt_result(sum_ct)
    expected_sum = sum(t for u, t in p2_data if u in common_users)

    print("\n=== Results ===")
    print(f"Intersection size: {len(indices)}")
    print(f"Computed sum: {result_sum}")
    print(f"Expected sum: {expected_sum}")
    print("Protocol", "succeeded" if result_sum == expected_sum else "failed")

if __name__ == "__main__":
    simulate_protocol()
