from party import Party1, Party2
import random

def simulate_protocol():
    print("=== DDH Private Intersection-Sum Protocol ===")

    common_users = ["user_%d" % i for i in range(5)]
    p1_data = common_users + ["unique_%d" % i for i in range(3)]
    p2_data = [(u, random.randint(10, 100)) for u in common_users] + \
              [("other_%d" % i, random.randint(10, 100)) for i in range(2)]

    random.shuffle(p1_data)
    random.shuffle(p2_data)

    print("\nInitial Data:")
    print(f"P1 set size: {len(p1_data)}")
    print(f"P2 set size: {len(p2_data)}")
    print(f"Expected intersection: {len(common_users)} items")

    p1 = Party1(p1_data)
    p2 = Party2(p2_data)

    p1.set_public_key(p2.get_public_key())

    print("\n=== Protocol Execution ===")
    round1_out = p1.round1()
    round2_out = p2.round2(round1_out)
    sum_ct, indices = p1.round3(*round2_out)
    result = p2.decrypt_result(sum_ct)

    expected_sum = sum(t for u, t in p2_data if u in common_users)

    print("\n=== Results ===")
    print(f"Intersection size: {len(indices)}")
    print(f"Computed sum: {result}")
    print(f"Expected sum: {expected_sum}")
    print("Protocol", "succeeded" if result == expected_sum else "failed")

if __name__ == "__main__":
    simulate_protocol()