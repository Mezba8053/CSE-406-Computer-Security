import time
import socket
import pickle
import threading
import os
import sys
import importlib
dh_module = importlib.import_module("2105005_dh")
aes_module = importlib.import_module("2105005_aes")
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
        cipher = aes_module.aes(key)
        ciphertext = cipher.encrypt(data, mode=mode)
        with open(out_path, 'wb') as f:
            f.write(ciphertext)
        return len(data), len(ciphertext)
    def image_encrypt(self, image_data, key, mode='CBC'):
        out = b''
        cipher = aes_module.aes(key)
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
        cipher = aes_module.aes(key)
        if mode=="ECB":
            for i in range(0, len(ciphertext), 16):
                out += cipher.decrypt_block(ciphertext[i:i + 16])
        elif mode=="CBC":
            iv = ciphertext[:16]
            ciphertext = ciphertext[16:]
            prev = iv
            for i in range(0, len(ciphertext), 16):
                block = ciphertext[i:i + 16]
                dec = cipher.decrypt_block(block)
                out += bytes(a ^ b for a, b in zip(dec, prev))
                prev = block
        return out

    def decrypt_file(self, in_path, out_path, key, mode='CBC'):
        with open(in_path, 'rb') as f:
            ciphertext = f.read()
        cipher = aes_module.aes(key)
        plaintext = cipher.decrypt(ciphertext, mode=mode)
        with open(out_path, 'wb') as f:
            f.write(plaintext)
        return len(plaintext)

    def test_aes(self, plaintext=None, key=None):
        key = "aes_key___________ _____     32b"
        plaintext = "Test message dedicated especially for encryption."

        print("=" * 80)
        print("TASK 1 : AES / ECB and CBC")
        print("=" * 80)

        ks_start = time.perf_counter()
        cipher = aes_module.aes(key)
        ks_end = time.perf_counter()
        key_schedule_time = ks_end - ks_start

        enc_start = time.perf_counter()
        ct_ecb = cipher.encrypt_ecb(plaintext)
        enc_end = time.perf_counter()
        enc_time_ecb = enc_end - enc_start

        
        print("\n===== ECB Mode =====")
        print("Key:")
        print("In ASCII: " + key)
        print("In HEX: " + key.encode().hex())
        print("\nPlain Text:")
        print("In ASCII: " + plaintext)
        print("In HEX: " + plaintext.encode().hex())
        print("\nCiphered text")
        print("In HEX: " + ct_ecb.hex())
        print("In ASCII: " + ct_ecb.decode(errors='ignore'))
        print("\nDeciphered Text:")
        # print("Before Unpadding:")
        dec_start = time.perf_counter()
        pt_ecb = cipher.decrypt_ecb(ct_ecb)
        dec_end = time.perf_counter()
        dec_time_ecb = dec_end - dec_start
        # print(pt_ecb.decode(errors='ignore'))
        print("After Unpading:")
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
        print("\nCiphertext :")
        print("IV: " + iv.hex())
        print("In HEX: " + ct_body.hex())
        print("In ASCII: " + ct_body.decode(errors='ignore'))
        print("\nDeciphered Text:")
        
        dec_start = time.perf_counter()
        pt_cbc = cipher.decrypt_cbc(ct_cbc)
        dec_end = time.perf_counter()
        print("After Unpadding:")
        print("In HEX: " + pt_cbc.hex())
        print("In ASCII: " + pt_cbc.decode())
        print("\nExecution Time Details:")
        print(f"Key Schedule Time: {key_schedule_time * 1000:.16f} ms")
        print(f"Encryption Time: {enc_time_cbc * 1000:.16f} ms")
        print(f"Decryption Time: {dec_time_cbc * 1000:.16f} ms")

    def test_dh(self):
        print("\n")
        print("=" * 80)
        print("TASK 2 : DIFFIE HELLMAN KEY EXCHANGE")
        print("=" * 80)
        self.key = ""
        key_sizes = [128, 192, 256]
        TRIALS = 5
        results = []
        for bits in key_sizes:
            totalA = 0
            totalB = 0
            totalShared = 0

            print("\n" + "=" * 60)
            print(f"Key Size: {bits} bits")
            print("=" * 60)

            for trial in range(TRIALS):
                p = dh_module.diffie_hellman(0, 0).generate_prime_number(bits)
                A = dh_module.diffie_hellman(p, 2)
                g = A.generate_generator()
                A.g = g

                B = dh_module.diffie_hellman(p, g)

                A.generate_private_key(bits)
                t0 = time.perf_counter()
                A.generate_public_key()
                t1 = time.perf_counter()

                B.generate_private_key(bits)
                t2 = time.perf_counter()
                B.generate_public_key()
                t3 = time.perf_counter()

                t4 = time.perf_counter()
                sharedA = A.compute_shared_secret(B.public_key)
                sharedB = B.compute_shared_secret(A.public_key)
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
                    print("\n--- A ---")
                    print("Private Key:")
                    print(A.private_key)
                    print("\nPublic Key:")
                    print(A.public_key)
                    print("\n--- B ---")
                    print("Private Key:")
                    print(B.private_key)
                    print("\nPublic Key:")
                    print(B.public_key)
                    print("\n--- Shared Secret ---")
                    print("Shared Secret (Decimal):")
                    print(sharedA)
                    print("\nShared Secret (HEX):")
                    print(hex(sharedA))

                    aes_key = dh_module.getkey_from_shared_secret(sharedA)
                    print("\nDerived AES Key (HEX):")
                    print(aes_key.hex())
                    self.key = aes_key
                    cipher = aes_module.aes(aes_key)
                    msg = "This message uses DH derived AES key."
                    ct = cipher.encrypt_cbc(msg)
                    recovered = cipher.decrypt_cbc(ct)

                    print("Original Message: " + msg)
                    print("Recovered Message: " + recovered.decode())

            avgA = (totalA / TRIALS) * 1000
            avgB = (totalB / TRIALS) * 1000
            avgShared = (totalShared / TRIALS) * 1000

            results.append((bits, avgA, avgB, avgShared))
        print("\n")
        print("=" * 70)
        print("Diffie-Hellman Timing Results")
        print("=" * 70)

        print(f"{'k':<10}{'A (ms)':<20}{'B (ms)':<20}{'shared key s (ms)':<20}")
        print("-" * 70)

        for bits, avgA, avgB, avgShared in results:
                print(f"{bits:<10}{avgA:<20.6f}{avgB:<20.6f}{avgShared:<20.6f}")


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
            # header = raw[:pixel_offset]
            with open("encrypted_cbc.bmp", "wb") as f:
                        f.write(header +val_cbc)
            ecb_img = Image.open("encrypted_ecb.bmp")
            cbc_img = Image.open("encrypted_cbc.bmp")
            w, h = ecb_img.size
            combined = Image.new("RGB", (w * 2 + 10, h), (255, 255, 255))
            combined.paste(ecb_img, (0, 0))
            combined.paste(cbc_img, (w + 10, 0))
            combined.save("ecb_vs_cbc_side_by_side.png")
            dec_ecb=r.image_decrypt(val_ecb, key, "ECB")
            dec_cbc=r.image_decrypt(val_cbc, key, "CBC")
            with open("decrypted_ecb.bmp", "wb") as f:
                        f.write(header+dec_ecb)
            with open("decrypted_cbc.bmp", "wb") as f:
                        f.write(header +dec_cbc)
            dec_ecb_img = Image.open("decrypted_ecb.bmp")
            dec_cbc_img = Image.open("decrypted_cbc.bmp")
            w, h = dec_ecb_img.size
            combined_dec = Image.new("RGB", (w * 2 + 10, h), (255, 255, 255))
            combined_dec.paste(dec_ecb_img, (0, 0))
            combined_dec.paste(dec_cbc_img, (w + 10, 0))
            combined_dec.save("decrypted_ecb_vs_cbc_side_by side.png")

        else:
                    pt_len = r.decrypt_file(in_path, out_path, key, mode)
                    print(f"Decrypted -> {pt_len} bytes -> {out_path}")
    else:
        r = runner()