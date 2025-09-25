import socket, subprocess, tempfile
from pathlib import Path

HOST, PORT = "127.0.0.1", 5000
CLIENT_KEY = "client.key"
CLIENT_CERT = "client.crt"
CA_CERT = "ca.crt"

def run(cmd):
    return subprocess.run(cmd, capture_output=True, check=True).stdout

def rsa_encrypt(data: bytes, pubkey_file: str) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        f.flush()
        return run(["openssl", "rsautl", "-encrypt", "-inkey", pubkey_file, "-pubin", "-in", f.name])

def sign_message(message: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as f_msg, tempfile.NamedTemporaryFile(delete=False) as f_sig:
        f_msg.write(message)
        f_msg.flush()
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", CLIENT_KEY, "-out", f_sig.name, f_msg.name],
            check=True
        )
        return Path(f_sig.name).read_bytes()

def verify_cert(cert_file: str) -> bool:
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", CA_CERT, cert_file],
        capture_output=True
    )
    return b"OK" in result.stdout

# --- Client workflow ---
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Receive server certificate
    length = int.from_bytes(s.recv(4), "big")
    server_cert = s.recv(length)
    server_cert_file = "server.crt"
    Path(server_cert_file).write_bytes(server_cert)

    if not verify_cert(server_cert_file):
        print("Server certificate not trusted.")
        exit(1)
    print("Server certificate verified.")

    # Extract server public key
    subprocess.run(
        ["openssl", "x509", "-in", server_cert_file, "-pubkey", "-noout"],
        stdout=open("server_pub.pem", "wb"), check=True
    )

    # Send client certificate
    cert_data = Path(CLIENT_CERT).read_bytes()
    s.sendall(len(cert_data).to_bytes(4, "big") + cert_data)

    # Message to send
    message = b"Hello Server, this is Client!"
    # Or read from a small file:
    # with open("message.txt", "rb") as f:
    #     message = f.read()

    ciphertext = rsa_encrypt(message, "server_pub.pem")
    signature = sign_message(message)

    s.sendall(len(ciphertext).to_bytes(4, "big") + ciphertext)
    s.sendall(len(signature).to_bytes(4, "big") + signature)

    print("Message and signature sent.")