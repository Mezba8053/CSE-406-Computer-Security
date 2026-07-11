from ast import In
import socket
import pickle
import importlib
dh_module = importlib.import_module("2105005_dh")
aes_module = importlib.import_module("2105005_aes")
runner_module=importlib.import_module("2105005_runner")
sock = socket.socket()
sock.connect(("localhost",5001))
p = dh_module.diffie_hellman(0, 0).generate_prime_number(128)
dh = dh_module.diffie_hellman(p, 2)
dh.p = p
dh.g = dh.generate_generator()
dh.generate_private_key(128)
dh.generate_public_key()
sock.sendall(
    pickle.dumps({
        "p":p,
        "g":dh.g,
        "A":dh.public_key}))
reply = pickle.loads(sock.recv(4096))
print("Enter Message to send to Bob:")
message = input()
B = reply["B"]
shared = dh.compute_shared_secret(B)
aes_key = dh_module.getkey_from_shared_secret(shared)
cipher = aes_module.aes(aes_key)
ciphertext = cipher.encrypt_cbc(message)
sock.sendall(ciphertext)