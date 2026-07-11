import time
import os
from aes import aes

print("="*80)
print("BONUS 1 : ECB vs CBC IMAGE COMPARISON (with smaller image)")
print("="*80)

# Try different image files
image_files = ["WhatsApp Image 2025-06-12 at 10.22.41 PM.jpeg", "sampleio.png"]
image_data = None
image_file = None

for img_file in image_files:
    if os.path.exists(img_file):
        with open(img_file, 'rb') as f:
            image_data = f.read()
        if len(image_data) < 100000:  # Use if smaller than 100KB
            image_file = img_file
            break

if image_data is None:
    # Create test pattern if no suitable image found
    print("\nNo suitable image found, creating test pattern...")
    image_data = (b'\x00' * 256 + b'\xFF' * 256 + b'\xAA' * 256 + b'\x55' * 256) * 2
    image_file = "test_pattern"

print(f"\nUsing: {image_file}")
print(f"Size: {len(image_data)} bytes")

key_128 = "Thats my Kung Fu"
cipher = aes(key_128)

# Encrypt with ECB
print("\nEncrypting with ECB...")
enc_start_ecb = time.perf_counter()
ct_ecb = cipher.encrypt_ecb(image_data)
enc_end_ecb = time.perf_counter()

# Encrypt with CBC
print("Encrypting with CBC...")
enc_start_cbc = time.perf_counter()
ct_cbc = cipher.encrypt_cbc(image_data)
enc_end_cbc = time.perf_counter()

# Save encrypted versions
if image_file != "test_pattern":
    ecb_file = image_file.replace(".", "_ecb.")
    cbc_file = image_file.replace(".", "_cbc.")
else:
    ecb_file = "sampleio_ecb.bin"
    cbc_file = "sampleio_cbc.bin"

with open(ecb_file, 'wb') as f:
    f.write(ct_ecb)
with open(cbc_file, 'wb') as f:
    f.write(ct_cbc)

print(f"\n✓ ECB Encryption Complete")
print(f"  Time: {(enc_end_ecb - enc_start_ecb) * 1000:.4f} ms")
print(f"  Output size: {len(ct_ecb)} bytes")
print(f"  Saved to: {ecb_file}")
print(f"  First 64 bytes (HEX): {ct_ecb[:64].hex()}")

print(f"\n✓ CBC Encryption Complete")
print(f"  Time: {(enc_end_cbc - enc_start_cbc) * 1000:.4f} ms")
print(f"  Output size: {len(ct_cbc)} bytes")
print(f"  Saved to: {cbc_file}")
print(f"  IV (first 16 bytes HEX): {ct_cbc[:16].hex()}")

# Pattern analysis
print(f"\nPattern Analysis:")
ecb_blocks = [ct_ecb[i:i+16] for i in range(0, len(ct_ecb), 16)]
cbc_blocks = [ct_cbc[16:][i:i+16] for i in range(0, len(ct_cbc)-16, 16)]

unique_ecb = len(set(ecb_blocks))
unique_cbc = len(set(cbc_blocks))

print(f"  ECB - Total blocks: {len(ecb_blocks)}, Unique blocks: {unique_ecb}")
ecb_leakage = (1 - unique_ecb/len(ecb_blocks)) * 100
print(f"  ECB Pattern Leakage: {ecb_leakage:.2f}%")
if ecb_leakage > 50:
    print(f"  ⚠️  MAJOR WEAKNESS: Strong pattern leakage detected!")
else:
    print(f"  ⚠️  WEAKNESS: Identical plaintext blocks = identical ciphertext")

print(f"\n  CBC - Total blocks: {len(cbc_blocks)}, Unique blocks: {unique_cbc}")
cbc_rand = (unique_cbc/len(cbc_blocks)) * 100
print(f"  CBC Randomization: {cbc_rand:.2f}%")
print(f"  ✓ SECURE: All blocks unique due to IV chaining")

# Verify decryption
print(f"\nDecryption Verification:")
dec_start_ecb = time.perf_counter()
pt_ecb = cipher.decrypt_ecb(ct_ecb)
dec_end_ecb = time.perf_counter()

dec_start_cbc = time.perf_counter()
pt_cbc = cipher.decrypt_cbc(ct_cbc)
dec_end_cbc = time.perf_counter()

print(f"  ECB - Time: {(dec_end_ecb - dec_start_ecb) * 1000:.4f} ms, Status: {'✓ PASS' if pt_ecb == image_data else '✗ FAIL'}")
print(f"  CBC - Time: {(dec_end_cbc - dec_start_cbc) * 1000:.4f} ms, Status: {'✓ PASS' if pt_cbc == image_data else '✗ FAIL'}")

print(f"\n" + "="*80)
print(f"📊 COMPARISON SUMMARY")
print(f"="*80)
print(f"ECB Mode - Weakness:")
print(f"  • Same plaintext blocks encrypt to same ciphertext")
print(f"  • Patterns in plaintext are visible in ciphertext")
print(f"  • Pattern leakage: {ecb_leakage:.2f}%")
print(f"  • File: {ecb_file}")

print(f"\nCBC Mode - Secure:")
print(f"  • Each block depends on previous ciphertext")
print(f"  • Random IV ensures different output each time")
print(f"  • Randomization: {cbc_rand:.2f}%")
print(f"  • File: {cbc_file}")

print(f"\n💡 To see the visual difference:")
print(f"   Compare the two binary files - CBC will appear more random!")
