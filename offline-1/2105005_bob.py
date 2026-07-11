import socket
import pickle
import importlib
aes_module=importlib.import_module("2105005_aes")
dh_module=importlib.import_module("2105005_dh")
import time
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost",5001))
server.listen(1)
conn,address = server.accept()
data = pickle.loads(conn.recv(4096))
p = data["p"]
g = data["g"]
A = data["A"]
print("Received from Alice:")
print("p:", p)
print("g:", g)
print("A:", A)
dh = dh_module.diffie_hellman(p, g)
dh.generate_private_key(128)
dh.generate_public_key()
conn.sendall(
    pickle.dumps({"B": dh.public_key}))
shared = dh.compute_shared_secret(A)
aes_key = dh_module.getkey_from_shared_secret(shared)
ks_start = time.perf_counter()
cipher = aes_module.aes(aes_key)
ks_end = time.perf_counter()
print("Key:\n")
print(f"In Hex: {aes_key.hex()}")
print(f"In ASCII: {aes_key.decode(errors='ignore')}")
key_schedule_time = ks_end - ks_start
ciphertext = conn.recv(4096)
print("Received ciphertext :")
print(f"In Hex: {ciphertext.hex()})")
print(f"In ASCII: {ciphertext.decode(errors='ignore')}")
dec_start=time.perf_counter()
plaintext = cipher.decrypt_cbc(ciphertext)
dec_end=time.perf_counter()
# print(plaintext.decode())
print("Execution Details ")
print("After Unpadding:")
print(f"In Hex: {plaintext.hex()}")
print(f"In ASCII: {plaintext.decode(errors='ignore')}")
key_time = cipher.get_key_expansion_time()
print(f"Key Schedule Time: {key_time}")
print(f"Encryption Time: {ks_end - ks_start}")
print(f"Decryption Time: {dec_end - dec_start}")