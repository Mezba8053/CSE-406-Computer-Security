import time
import socket
import pickle
import threading
import os
import sys
from aes import aes
from dh import diffie_hellman, getkey_from_shared_secret
from PIL import Image
IMG_SIZE = (64, 64)  
class runner:
    def __init__(self, run_tests=True):
        if run_tests:
            self.run_all_tests()

    def run_all_tests(self):
        self.test_aes()
        self.test_dh()          
        # self.test_image()
        
    def encrypt_file(self, in_path, out_path, key, mode='CBC'):
        with open(in_path, 'rb') as f:
            data = f.read()
        cipher = aes(key)
        ciphertext = cipher.encrypt(data, mode=mode)
        with open(out_path, 'wb') as f:
            f.write(ciphertext)
        return len(data), len(ciphertext)
    def image_encrypt(self, image_data, key, mode='CBC'):
        out = b''
        cipher = aes(key)
        if mode=="ECB":
            for i in range(0, len(image_data), 16):
                out += cipher.encrypt_block(image_data[i:i + 16])
        elif mode=="CBC":
            iv = os.urandom(16)
            out += iv
            prev = iv
            for i in range(0, len(image_data), 16):
                block = bytes(a ^ b for a, b in zip(image_data[i:i + 16], prev))
                enc = cipher.encrypt_block(block)
                out += enc
                prev = enc
        return out
    def image_decrypt(self, ciphertext, key, mode='CBC'):
        out = b''
        cipher = aes(key)
        for i in range(0, len(ciphertext), 16):
            out += cipher.decrypt_block(ciphertext[i:i + 16])
        return out

    def decrypt_file(self, in_path, out_path, key, mode='CBC'):
        with open(in_path, 'rb') as f:
            ciphertext = f.read()
        cipher = aes(key)
        plaintext = cipher.decrypt(ciphertext, mode=mode)
        with open(out_path, 'wb') as f:
            f.write(plaintext)
        return len(plaintext)

    def test_aes(self, plaintext=None, key=None):
        key = "aes_key___________ _____     32b"
        plaintext = "Test message desdicated especially for encryption."

        print("=" * 80)
        print("TASK 1 : AES / ECB and CBC")
        print("=" * 80)

        ks_start = time.perf_counter()
        cipher = aes(key)
        ks_end = time.perf_counter()
        key_schedule_time = ks_end - ks_start

        enc_start = time.perf_counter()
        ct_ecb = cipher.encrypt_ecb(plaintext)
        enc_end = time.perf_counter()
        enc_time_ecb = enc_end - enc_start

        dec_start = time.perf_counter()
        pt_ecb = cipher.decrypt_ecb(ct_ecb)
        dec_end = time.perf_counter()
        dec_time_ecb = dec_end - dec_start

        print("\n===== ECB Mode =====")
        print("Key:")
        print("In ASCII: " + key)
        print("In HEX: " + key.encode().hex())
        print("\nPlain Text:")
        print("In ASCII: " + plaintext)
        print("In HEX: " + plaintext.encode().hex())
        print("\nCiphertext (HEX):")
        print(ct_ecb.hex())
        print("\nDeciphered Text:")
        print("In HEX: " + pt_ecb.hex())
        print("In ASCII: " + pt_ecb.decode())
        print("\nExecution Time Details:")
        print(f"Key Schedule Time: {key_schedule_time * 1000:.16f} ms")
        print(f"Encryption Time: {enc_time_ecb * 1000:.16f} ms")
        print(f"Decryption Time: {dec_time_ecb * 1000:.16f} ms")

        enc_start = time.perf_counter()
        ct_cbc = cipher.encrypt_cbc(plaintext)
        enc_end = time.perf_counter()
        enc_time_cbc = enc_end - enc_start

        dec_start = time.perf_counter()
        pt_cbc = cipher.decrypt_cbc(ct_cbc)
        dec_end = time.perf_counter()
        dec_time_cbc = dec_end - dec_start
        print("\n===== CBC Mode =====")
        print("Key:")
        print("In ASCII: " + key)
        print("In HEX: " + key.encode().hex())
        print("\nPlain Text:")
        print("In ASCII: " + plaintext)
        print("In HEX: " + plaintext.encode().hex())
        iv = ct_cbc[:16]
        ct_body = ct_cbc[16:]
        print("\nCiphertext (HEX):")
        print("(IV is the first 16 bytes, followed by the actual ciphertext)")
        print("IV: " + iv.hex())
        print("Ciphertext: " + ct_body.hex())
        print("\nDeciphered Text:")
        print("In ASCII: " + pt_cbc.decode())
        print("\nExecution Time Details:")
        print(f"Key Schedule Time: {key_schedule_time * 1000:.16f} ms")
        print(f"Encryption Time: {enc_time_cbc * 1000:.16f} ms")
        print(f"Decryption Time: {dec_time_cbc * 1000:.16f} ms")

    def test_dh(self):
        """Test Diffie-Hellman key exchange"""
        print("\n")
        print("=" * 80)
        print("TASK 2 : DIFFIE HELLMAN KEY EXCHANGE")
        print("=" * 80)
        self.key = ""
        key_sizes = [128, 192, 256]
        TRIALS = 5

        for bits in key_sizes:
            totalA = 0
            totalB = 0
            totalShared = 0

            print("\n" + "=" * 60)
            print(f"Key Size: {bits} bits")
            print("=" * 60)

            for trial in range(TRIALS):
                p = diffie_hellman(0, 0).generate_prime_number(bits)
                alice = diffie_hellman(p, 2)
                g = alice.generate_generator()
                alice.g = g

                bob = diffie_hellman(p, g)

                alice.generate_private_key(bits)
                t0 = time.perf_counter()
                alice.generate_public_key()
                t1 = time.perf_counter()

                bob.generate_private_key(bits)
                t2 = time.perf_counter()
                bob.generate_public_key()
                t3 = time.perf_counter()

                t4 = time.perf_counter()
                sharedA = alice.compute_shared_secret(bob.public_key)
                sharedB = bob.compute_shared_secret(alice.public_key)
                t5 = time.perf_counter()

                assert sharedA == sharedB, "Shared secrets don't match!"

                totalA += (t1 - t0)
                totalB += (t3 - t2)
                totalShared += (t5 - t4)

                if trial == 0:
                    print("\n[Trial 1 - Detailed Output]")
                    print("\nPrime P:")
                    print(p)
                    print("\nGenerator g:")
                    print(g)
                    print("\n--- Alice ---")
                    print("Private Key:")
                    print(alice.private_key)
                    print("\nPublic Key:")
                    print(alice.public_key)
                    print("\n--- Bob ---")
                    print("Private Key:")
                    print(bob.private_key)
                    print("\nPublic Key:")
                    print(bob.public_key)
                    print("\n--- Shared Secret ---")
                    print("Shared Secret (Decimal):")
                    print(sharedA)
                    print("\nShared Secret (HEX):")
                    print(hex(sharedA))

                    aes_key = getkey_from_shared_secret(sharedA)
                    print("\nDerived AES Key (HEX):")
                    print(aes_key.hex())
                    self.key = aes_key
                    cipher = aes(aes_key)
                    msg = "This message uses DH derived AES key."
                    ct = cipher.encrypt_cbc(msg)
                    recovered = cipher.decrypt_cbc(ct)

                    print("\nMessage Verification:")
                    print("Original Message: " + msg)
                    print("Recovered Message: " + recovered.decode())

            print("\n[Average Performance]")
            print(f"Average Public Key Generation Time (Alice): {totalA/TRIALS:.16f} seconds ({(totalA/TRIALS)*1000:.16f} ms)")
            print(f"Average Public Key Generation Time (Bob):   {totalB/TRIALS:.16f} seconds ({(totalB/TRIALS)*1000:.16f} ms)")
            print(f"Average Shared Secret Computation:          {totalShared/TRIALS:.16f} seconds ({(totalShared/TRIALS)*1000:.16f} ms)")


if __name__ == "__main__":
    if len(sys.argv) >= 5 and sys.argv[1] in ("encrypt", "decrypt", "image"):
        action, in_path, out_path, key = sys.argv[1:5]
        mode = sys.argv[5] if len(sys.argv) > 5 else 'CBC'

        r = runner(run_tests=False)
        if action == 'encrypt':
            orig_len, ct_len = r.encrypt_file(in_path, out_path, key, mode)
            print(f"Encrypted {orig_len} bytes -> {ct_len} bytes ({mode}) -> {out_path}")
        elif action=='image':
            img = Image.open(in_path).convert("RGB").resize(IMG_SIZE)
            img.save("input_64x64.bmp")
 
            with open("input_64x64.bmp", "rb") as f:
                raw = bytearray(f.read())
            pixel_offset = int.from_bytes(raw[10:14], "little")
            header = raw[:pixel_offset]
            pixel_data = bytes(raw[pixel_offset:])
            val_ecb=r.image_encrypt(pixel_data, key, "ECB")
            val_cbc=r.image_encrypt(pixel_data, key, "CBC")
            
            with open("encrypted_ecb.bmp", "wb") as f:
                        f.write(header+val_ecb)
            header = raw[:pixel_offset]
            with open("encrypted_cbc.bmp", "wb") as f:
                        f.write(header +val_cbc)
            ecb_img = Image.open("encrypted_ecb.bmp")
            cbc_img = Image.open("encrypted_cbc.bmp")
            w, h = ecb_img.size
            combined = Image.new("RGB", (w * 2 + 10, h), (255, 255, 255))
            combined.paste(ecb_img, (0, 0))
            combined.paste(cbc_img, (w + 10, 0))
            combined.save("ecb_vs_cbc_side_by_side.png")
 

        else:
                    pt_len = r.decrypt_file(in_path, out_path, key, mode)
                    print(f"Decrypted -> {pt_len} bytes -> {out_path}")
    # else:
    #     r = runner()