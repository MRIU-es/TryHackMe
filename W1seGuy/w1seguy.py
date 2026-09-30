import socket
import string

HOST, PORT = "10.112.175.206", 1337

# --- 1. Connect and capture the ciphertext (keep this connection open) ---
s = socket.create_connection((HOST, PORT))
data = b""
while b"encryption key?" not in data:
    data += s.recv(4096)

banner = data.decode()
hex_ct = banner.split("flag 1:")[1].split()[0]
ct = bytes.fromhex(hex_ct)

# --- 2. Recover the ONLY guaranteed known plaintext: "THM{" (4 bytes) ---
known_prefix = b"THM{"
key_chars = [chr(ct[i] ^ known_prefix[i]) for i in range(len(known_prefix))]

# --- 3. Brute-force the 5th key character (62 alphanumeric options)
flag1 = None
full_key = None
for c in string.ascii_letters + string.digits:
    candidate = key_chars + [c]
    pt = bytes(ct[i] ^ ord(candidate[i % 5]) for i in range(len(ct)))
    if pt.endswith(b"}") and all(32 <= b < 127 for b in pt):
        full_key = "".join(candidate)
        flag1 = pt.decode()
        break

if not full_key:
    raise SystemExit("Could not recover key - check the captured hex/offsets.")

print("Recovered key:", full_key)
print("Flag 1:", flag1)

# --- 4. Submit the key on the SAME connection to get flag 2 ---
s.send((full_key + "\n").encode())
response = s.recv(4096).decode()
s.close()

print("Server response:", response)
