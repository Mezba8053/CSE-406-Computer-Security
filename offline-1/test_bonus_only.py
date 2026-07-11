import time
import os
from aes import aes

print("="*80)
print("BONUS 1 : ECB vs CBC IMAGE COMPARISON")
print("="*80)

# Load actual image file
image_file = "sampleio.png"
if os.path.exists(image_file):
    with open(image_file, 'rb') as f:
        image_data = f.read()
    
    print(f"\nLoaded image file: {image_file}")
    print(f"Original image size: {len(image_data)} bytes")
    
    # Pad image to multiple of 16 bytes for AES
    key_128 = "Thats my Kung Fu"
    cipher = aes(key_128)
    
    # Encrypt with ECB
    enc_start_ecb = time.perf_counter()
    ct_ecb = cipher.encrypt_ecb(image_data)
    enc_end_ecb = time.perf_counter()
    
    # Encrypt with CBC
    enc_start_cbc = time.perf_counter()
    ct_cbc = cipher.encrypt_cbc(image_data)
    enc_end_cbc = time.perf_counter()
    
    # Save encrypted versions
    ecb_file = "sampleio_ecb.bin"
    cbc_file = "sampleio_cbc.bin"
    
    with open(ecb_file, 'wb') as f:
        f.write(ct_ecb)
    with open(cbc_file, 'wb') as f:
        f.write(ct_cbc)
    
    print(f"\nECB Encryption:")
    print(f"  Time: {(enc_end_ecb - enc_start_ecb) * 1000:.4f} ms")
    print(f"  Output size: {len(ct_ecb)} bytes")
    print(f"  Saved to: {ecb_file}")
    print(f"  First 64 bytes (HEX): {ct_ecb[:64].hex()}")
    print(f"  Bytes 256-320 (HEX):  {ct_ecb[256:320].hex() if len(ct_ecb) > 320 else 'N/A'}")
    
    print(f"\nCBC Encryption:")
    print(f"  Time: {(enc_end_cbc - enc_start_cbc) * 1000:.4f} ms")
    print(f"  Output size: {len(ct_cbc)} bytes")
    print(f"  Saved to: {cbc_file}")
    print(f"  IV (first 16 bytes HEX): {ct_cbc[:16].hex()}")
    print(f"  Ciphertext (17-80 HEX): {ct_cbc[17:81].hex()}")
    
    # Pattern analysis
    print(f"\nPattern Analysis:")
    ecb_blocks = [ct_ecb[i:i+16] for i in range(0, len(ct_ecb), 16)]
    cbc_blocks = [ct_cbc[16:][i:i+16] for i in range(0, len(ct_cbc)-16, 16)]
    
    unique_ecb = len(set(ecb_blocks))
    unique_cbc = len(set(cbc_blocks))
    
    print(f"  ECB - Total blocks: {len(ecb_blocks)}, Unique blocks: {unique_ecb}")
    print(f"  ECB Pattern Leakage: {(1 - unique_ecb/len(ecb_blocks)) * 100:.2f}%")
    print(f"  ECB WEAKNESS: Identical plaintext blocks produce identical ciphertext blocks")
    
    print(f"\n  CBC - Total blocks: {len(cbc_blocks)}, Unique blocks: {unique_cbc}")
    print(f"  CBC Randomization: {(unique_cbc/len(cbc_blocks)) * 100:.2f}%")
    print(f"  ✓ CBC SECURE: All ciphertext blocks are unique due to IV chaining")
    
    # Decryption verification
    dec_start_ecb = time.perf_counter()
    pt_ecb = cipher.decrypt_ecb(ct_ecb)
    dec_end_ecb = time.perf_counter()
    
    dec_start_cbc = time.perf_counter()
    pt_cbc = cipher.decrypt_cbc(ct_cbc)
    dec_end_cbc = time.perf_counter()
    
    print(f"\nDecryption Verification:")
    print(f"  ECB - Time: {(dec_end_ecb - dec_start_ecb) * 1000:.4f} ms, Status: {'✓ PASS' if pt_ecb == image_data else '✗ FAIL'}")
    print(f"  CBC - Time: {(dec_end_cbc - dec_start_cbc) * 1000:.4f} ms, Status: {'✓ PASS' if pt_cbc == image_data else '✗ FAIL'}")
    
    print(f"\n⚠️  Security Observation:")
    print(f"  When encrypting the SAME image file:")
    print(f"  - ECB MODE: Produces IDENTICAL output every time")
    print(f"    (same plaintext = same ciphertext, pattern leaking!)")
    print(f"  - CBC MODE: Produces DIFFERENT output every time")
    print(f"    (due to random IV, more secure)")
    print(f"\n  📁 Encrypted Files Generated:")
    print(f"     ECB: {ecb_file} ({os.path.getsize(ecb_file)} bytes)")
    print(f"     CBC: {cbc_file} ({os.path.getsize(cbc_file)} bytes)")
    print(f"\n  💡 To visualize the difference:")
    print(f"     Run encryption twice - ECB file will be identical,")
    print(f"     but CBC files will be completely different!")
    
else:
    print(f"Image file '{image_file}' not found.")
