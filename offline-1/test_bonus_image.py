import time
import os
from aes import aes

print("="*80)
print("BONUS 1 : ECB vs CBC IMAGE COMPARISON")
print("="*80)

# Create a small test image with recognizable pattern
# Total 4KB to keep encryption fast
print("\nGenerating test image (4KB with recognizable pattern)...")
test_image = b''
# Create a pattern that shows ECB weakness: alternating black (0x00) and white (0xFF) sections
test_image += b'\x00' * 256  # Black section
test_image += b'\xFF' * 256  # White section
test_image += b'\x00' * 256  # Black section again
test_image += b'\xFF' * 256  # White section again
test_image += b'\xAA' * 256  # Gray section (repeating pattern)
test_image += b'\x55' * 256  # Darker gray section
test_image += b'\xAA' * 256  # Gray section again
test_image += b'\x55' * 256  # Darker gray section again
test_image += b'\x00' * 512  # More black
test_image += b'\xFF' * 512  # More white

print(f"Test image size: {len(test_image)} bytes")

key_128 = "Thats my Kung Fu"
cipher = aes(key_128)

# Encrypt with ECB
print("\nEncrypting with ECB mode...")
enc_start_ecb = time.perf_counter()
ct_ecb = cipher.encrypt_ecb(test_image)
enc_end_ecb = time.perf_counter()
ecb_time = (enc_end_ecb - enc_start_ecb) * 1000

# Encrypt with CBC
print("Encrypting with CBC mode...")
enc_start_cbc = time.perf_counter()
ct_cbc = cipher.encrypt_cbc(test_image)
enc_end_cbc = time.perf_counter()
cbc_time = (enc_end_cbc - enc_start_cbc) * 1000

# Save encrypted versions
with open("sampleio_ecb.bin", 'wb') as f:
    f.write(ct_ecb)
with open("sampleio_cbc.bin", 'wb') as f:
    f.write(ct_cbc)

print(f"\n✓ Encryption Complete!")
print(f"\nECB Mode:")
print(f"  Time: {ecb_time:.4f} ms")
print(f"  Output size: {len(ct_ecb)} bytes")
print(f"  Saved to: sampleio_ecb.bin")
print(f"  First 32 bytes (HEX): {ct_ecb[:32].hex()}")
print(f"  Bytes 256-272 (HEX):  {ct_ecb[256:272].hex()}")
print(f"  Bytes 512-528 (HEX):  {ct_ecb[512:528].hex()}")

print(f"\nCBC Mode:")
print(f"  Time: {cbc_time:.4f} ms")
print(f"  Output size: {len(ct_cbc)} bytes")
print(f"  Saved to: sampleio_cbc.bin")
print(f"  IV (first 16 bytes HEX): {ct_cbc[:16].hex()}")
print(f"  Bytes 0-16 (HEX):        {ct_cbc[:16].hex()}")
print(f"  Bytes 16-32 (HEX):       {ct_cbc[16:32].hex()}")
print(f"  Bytes 256-272 (HEX):     {ct_cbc[256:272].hex()}")

# Pattern analysis
print(f"\n" + "="*60)
print("PATTERN ANALYSIS")
print("="*60)

ecb_blocks = [ct_ecb[i:i+16] for i in range(0, len(ct_ecb), 16)]
cbc_blocks = [ct_cbc[16:][i:i+16] for i in range(0, len(ct_cbc)-16, 16)]

unique_ecb = len(set(ecb_blocks))
unique_cbc = len(set(cbc_blocks))

print(f"\nECB Analysis:")
print(f"  Total blocks: {len(ecb_blocks)}")
print(f"  Unique blocks: {unique_ecb}")
ecb_leakage = (1 - unique_ecb/len(ecb_blocks)) * 100
print(f"  Pattern Leakage: {ecb_leakage:.2f}%")

print(f"\nCBC Analysis:")
print(f"  Total blocks: {len(cbc_blocks)}")
print(f"  Unique blocks: {unique_cbc}")
cbc_rand = (unique_cbc/len(cbc_blocks)) * 100
print(f"  Randomization: {cbc_rand:.2f}%")

# Compare specific sections
print(f"\n" + "="*60)
print("SECTION COMPARISON (showing ECB weakness)")
print("="*60)

print(f"\nSection 1 (bytes 0-256): All 0x00 (black)")
print(f"  ECB blocks 0: {ct_ecb[0:16].hex()}")
print(f"  ECB blocks 1: {ct_ecb[16:32].hex()}")
print(f"  ECB blocks 2: {ct_ecb[32:48].hex()}")
print(f"  ⚠️  Notice: ECB blocks are IDENTICAL (same plaintext = same ciphertext)")

print(f"\nSection 2 (bytes 256-512): All 0xFF (white)")
print(f"  ECB blocks 16: {ct_ecb[256:272].hex()}")
print(f"  ECB blocks 17: {ct_ecb[272:288].hex()}")
print(f"  ECB blocks 18: {ct_ecb[288:304].hex()}")
print(f"  ⚠️  Notice: ECB blocks are IDENTICAL")

print(f"\nSection 1 (bytes 0-256): All 0x00 (black)")
print(f"  CBC blocks 0: {ct_cbc[16:32].hex()}")
print(f"  CBC blocks 1: {ct_cbc[32:48].hex()}")
print(f"  CBC blocks 2: {ct_cbc[48:64].hex()}")
print(f"  ✓ Notice: CBC blocks are ALL DIFFERENT (secure!)")

print(f"\nSection 2 (bytes 256-512): All 0xFF (white)")
print(f"  CBC blocks 16: {ct_cbc[272:288].hex()}")
print(f"  CBC blocks 17: {ct_cbc[288:304].hex()}")
print(f"  CBC blocks 18: {ct_cbc[304:320].hex()}")
print(f"  ✓ Notice: CBC blocks are ALL DIFFERENT (secure!)")

# Verify decryption works
print(f"\n" + "="*60)
print("DECRYPTION VERIFICATION")
print("="*60)

pt_ecb = cipher.decrypt_ecb(ct_ecb)
pt_cbc = cipher.decrypt_cbc(ct_cbc)

print(f"ECB Decryption: {'✓ PASS' if pt_ecb == test_image else '✗ FAIL'}")
print(f"CBC Decryption: {'✓ PASS' if pt_cbc == test_image else '✗ FAIL'}")

# Final summary
print(f"\n" + "="*80)
print("CONCLUSION")
print("="*80)
print(f"""
ECB MODE - INSECURE for image encryption:
  ❌ Identical plaintext blocks → identical ciphertext blocks
  ❌ Patterns in the plaintext are visible in the ciphertext
  ❌ Pattern leakage: {ecb_leakage:.2f}%
  ❌ If you encrypt the same image twice, you get the SAME output
  
  📍 Files: sampleio_ecb.bin

CBC MODE - SECURE for image encryption:
  ✓ Random IV ensures different output each run
  ✓ Chaining mode: each block depends on previous ciphertext
  ✓ Randomization: {cbc_rand:.2f}%
  ✓ If you encrypt the same image twice, you get DIFFERENT output
  
  📍 Files: sampleio_cbc.bin

RECOMMENDATION:
  Always use CBC (or other secure modes) for encrypting real data!
  ECB is only suitable for educational purposes.
""")
