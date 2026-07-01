import time
# from Crypto.Util.number import getPrime
from aes import aes
from dh import diffie_hellman, getkey_from_shared_secret 

if __name__ == "__main__":

    plaintext = "Hello, AES! This is a test message for ECB and CBC modes."

    print("="*80)
    print("TASK 1 : AES")
    print("="*80)

    key = "Thats my Kung Fu"

    # ---------------- KEY SCHEDULE ----------------
    ks_start = time.perf_counter()
    cipher = aes(key)
    ks_end = time.perf_counter()

    # ---------------- ECB ----------------

    enc_start = time.perf_counter()
    ct_ecb = cipher.encrypt_ecb(plaintext)
    enc_end = time.perf_counter()

    dec_start = time.perf_counter()
    pt_ecb = cipher.decrypt_ecb(ct_ecb)
    dec_end = time.perf_counter()

    print("\n===== ECB =====")
    print("Key (ASCII) :", key)
    print("Key (HEX)   :", key.encode().hex())

    print("Plaintext (ASCII):", plaintext)
    print("Plaintext (HEX)  :", plaintext.encode().hex())

    print("Ciphertext (HEX) :", ct_ecb.hex())

    print("Recovered (ASCII):", pt_ecb.decode())
    print("Recovered (HEX)  :", pt_ecb.hex())

    print("Key Schedule Time :", ks_end-ks_start)
    print("Encryption Time   :", enc_end-enc_start)
    print("Decryption Time   :", dec_end-dec_start)

    # ---------------- CBC ----------------

    enc_start = time.perf_counter()
    ct_cbc = cipher.encrypt_cbc(plaintext)
    enc_end = time.perf_counter()

    dec_start = time.perf_counter()
    pt_cbc = cipher.decrypt_cbc(ct_cbc)
    dec_end = time.perf_counter()

    print("\n===== CBC =====")
    print("Key (ASCII) :", key)
    print("Key (HEX)   :", key.encode().hex())

    print("Plaintext (ASCII):", plaintext)
    print("Plaintext (HEX)  :", plaintext.encode().hex())

    print("Ciphertext (HEX) :", ct_cbc.hex())

    print("Recovered (ASCII):", pt_cbc.decode())
    print("Recovered (HEX)  :", pt_cbc.hex())

    print("Key Schedule Time :", ks_end-ks_start)
    print("Encryption Time   :", enc_end-enc_start)
    print("Decryption Time   :", dec_end-dec_start)

    ####################################################################
    print("\n")
    print("="*80)
    print("TASK 2 : DIFFIE HELLMAN")
    print("="*80)

    key_sizes = [128,192,256]

    TRIALS = 5

    for bits in key_sizes:

        totalA = 0
        totalB = 0
        totalShared = 0

        print("\n")
        print("="*60)
        print(bits,"bit")
        print("="*60)

        for trial in range(TRIALS):

            p = getPrime(bits)

            alice = diffie_hellman(p,2)

            g = alice.generate_generator()

            alice.g = g

            bob = diffie_hellman(p,g)

            #################### Alice ####################

            alice.generate_private_key(bits)

            t0 = time.perf_counter()
            alice.generate_public_key()
            t1 = time.perf_counter()

            #################### Bob ####################

            bob.generate_private_key(bits)

            t2 = time.perf_counter()
            bob.generate_public_key()
            t3 = time.perf_counter()

            #################### Shared Secret ####################

            t4 = time.perf_counter()

            sharedA = alice.compute_shared_secret(bob.public_key)
            sharedB = bob.compute_shared_secret(alice.public_key)

            t5 = time.perf_counter()

            assert sharedA == sharedB

            totalA += (t1-t0)
            totalB += (t3-t2)
            totalShared += (t5-t4)

            if trial == 0:

                print("Prime P :")
                print(p)

                print("\nGenerator g :")
                print(g)

                print("\nAlice Private :")
                print(alice.private_key)

                print("\nAlice Public :")
                print(alice.public_key)

                print("\nBob Private :")
                print(bob.private_key)

                print("\nBob Public :")
                print(bob.public_key)

                print("\nShared Secret :")
                print(sharedA)

                aes_key = getkey_from_shared_secret(sharedA)

                print("\nDerived AES Key (HEX)")
                print(aes_key.hex())

                cipher = aes(aes_key)

                msg = "This message uses DH derived AES key."

                ct = cipher.encrypt_cbc(msg)

                recovered = cipher.decrypt_cbc(ct)

                print("\nOriginal Message:")
                print(msg)

                print("\nCiphertext:")
                print(ct.hex())

                print("\nRecovered:")
                print(recovered.decode())

        print("\nAverage Public Key Generation Time (Alice):",
              totalA/TRIALS)

        print("Average Public Key Generation Time (Bob):",
              totalB/TRIALS)

        print("Average Shared Secret Computation:",
              totalShared/TRIALS)