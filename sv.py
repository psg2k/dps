import socket, subprocess, tempfile
from pathlib import Path

HOST, PORT = "127.0.0.1", 6000
SERVER_KEY = "server.key"
SERVER_CERT = "server.crt"
CA_CERT = "ca.crt"

def run(cmd):
    return subprocess.run(cmd, capture_output=True, check=True).stdout

def rsa_decrypt(ciphertext: bytes) -> bytes:
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(ciphertext)
    f.flush(); f.close()
    return run(["openssl", "rsautl", "-decrypt", "-inkey", SERVER_KEY, "-in", f.name])

def verify_cert(cert_file: str) -> bool:
    res = subprocess.run(["openssl", "verify", "-CAfile", CA_CERT, cert_file], capture_output=True)
    return b"OK" in res.stdout

def verify_signature(message: bytes, signature: bytes, cert_file: str) -> bool:
    pubkey_file = "client_pub.pem"
    subprocess.run(["openssl", "x509", "-in", cert_file, "-pubkey", "-noout"],
                   stdout=open(pubkey_file, "wb"), check=True)
    f_msg = tempfile.NamedTemporaryFile(delete=False)
    f_sig = tempfile.NamedTemporaryFile(delete=False)
    f_msg.write(message); f_msg.flush(); f_msg.close()
    f_sig.write(signature); f_sig.flush(); f_sig.close()
    res = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pubkey_file,
                          "-signature", f_sig.name, f_msg.name], capture_output=True)
    return b"Verified OK" in res.stdout

votes = [0, 0, 0]  # 3 contestants

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(3)
    print("Voting server started. Waiting for voters...")

    for i in range(3):
        conn, addr = s.accept()
        with conn:
            print(f"Voter {i+1} connected:", addr)

            # --- Send server certificate ---
            cert_data = Path(SERVER_CERT).read_bytes()
            conn.sendall(len(cert_data).to_bytes(4, "big") + cert_data)

            # --- Receive client certificate ---
            length = int.from_bytes(conn.recv(4), "big")
            client_cert = conn.recv(length)
            client_cert_file = f"client{i+1}.crt"
            Path(client_cert_file).write_bytes(client_cert)

            if not verify_cert(client_cert_file):
                print("Client certificate not trusted.")
                conn.close()
                continue
            print("Client certificate verified.")

            # --- Receive encrypted & signed vote ---
            length = int.from_bytes(conn.recv(4), "big")
            ciphertext = conn.recv(length)

            length_sig = int.from_bytes(conn.recv(4), "big")
            signature = conn.recv(length_sig)

            vote_plain = rsa_decrypt(ciphertext)
            if not verify_signature(vote_plain, signature, client_cert_file):
                print("Signature verification failed. Vote ignored.")
                continue

            bits = list(map(int, vote_plain.decode().split()))
            for j in range(3):
                votes[j] += bits[j]
            print(f"Vote from voter {i+1} counted: {bits}")

# --- Print result ---
print("\n--- Voting Result ---")
for idx, count in enumerate(votes, 1):
    print(f"Contestant {idx}: {count} votes")
winner = votes.index(max(votes)) + 1
print(f"\nWinner: Contestant {winner}")