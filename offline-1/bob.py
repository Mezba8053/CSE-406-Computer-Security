import socket
import pickle
from aes import aes
from dh import diffie_hellman, getkey_from_shared_secret
  

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost",5000))
server.listen(1)

conn,address = server.accept()

data = pickle.loads(conn.recv(4096))

p = data["p"]
g = data["g"]
A = data["A"]

# Bob:
dh = diffie_hellman(p,g)
dh.generate_private_key(128)
dh.generate_public_key()

conn.sendall(
    pickle.dumps({"B":dh.public_key})
)

shared = dh.compute_shared_secret(A)

aes_key = getkey_from_shared_secret(shared)

cipher = aes(aes_key)

ciphertext = conn.recv(4096)

plaintext = cipher.decrypt_cbc(ciphertext)

print(plaintext.decode())