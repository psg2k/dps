import socket, subprocess, tempfile, time
from pathlib import Path

HOST, PORT = "127.0.0.1", 5000
SERVER_KEY = "server.key"
SERVER_CERT = "server.crt"
CA_CERT = "ca.crt"

def run(cmd):
    return subprocess.run(cmd, capture_output=True, check=True).stdout

def rsa_decrypt(ciphertext: bytes) -> bytes:
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(ciphertext)
    f.flush()
    f.close()
    decrypted = run(["openssl", "rsautl", "-decrypt", "-inkey", SERVER_KEY, "-in", f.name])
    return decrypted

def rsa_encrypt(message: bytes, pubkey_file: str) -> bytes:
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(message)
    f.flush()
    f.close()
    encrypted = run(["openssl", "rsautl", "-encrypt", "-inkey", pubkey_file, "-pubin", "-in", f.name])
    return encrypted

def sign_message(message: bytes) -> bytes:
    f_msg = tempfile.NamedTemporaryFile(delete=False)
    f_sig = tempfile.NamedTemporaryFile(delete=False)
    f_msg.write(message); f_msg.flush(); f_msg.close()
    f_sig.flush(); f_sig.close()
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", SERVER_KEY, "-out", f_sig.name, f_msg.name],
        check=True
    )
    return Path(f_sig.name).read_bytes()

def verify_signature(message: bytes, signature: bytes, client_cert: str) -> bool:
    pubkey_file = "client_pub.pem"
    subprocess.run(
        ["openssl", "x509", "-in", client_cert, "-pubkey", "-noout"],
        stdout=open(pubkey_file, "wb"), check=True
    )
    f_msg = tempfile.NamedTemporaryFile(delete=False)
    f_sig = tempfile.NamedTemporaryFile(delete=False)
    f_msg.write(message); f_msg.flush(); f_msg.close()
    f_sig.write(signature); f_sig.flush(); f_sig.close()
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", pubkey_file, "-signature", f_sig.name, f_msg.name],
        capture_output=True
    )
    return b"Verified OK" in result.stdout

def verify_cert(cert_file: str) -> bool:
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", CA_CERT, cert_file],
        capture_output=True
    )
    return b"OK" in result.stdout

# --- Server workflow ---
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print("Server listening...")
    conn, addr = s.accept()
    with conn:
        print("Connected:", addr)

        # Send server certificate
        cert_data = Path(SERVER_CERT).read_bytes()
        conn.sendall(len(cert_data).to_bytes(4, "big") + cert_data)

        # Receive client certificate
        length = int.from_bytes(conn.recv(4), "big")
        client_cert = conn.recv(length)
        client_cert_file = "client.crt"
        Path(client_cert_file).write_bytes(client_cert)

        if not verify_cert(client_cert_file):
            print("Client certificate not trusted.")
            conn.close()
        else:
            print("Client certificate verified. Ready for secure communication.\n")

            while True:
                # Receive message from client
                length_bytes = conn.recv(4)
                if not length_bytes:
                    print("Connection closed by client.")
                    break
                length = int.from_bytes(length_bytes, "big")
                ciphertext = conn.recv(length)

                plaintext = rsa_decrypt(ciphertext)

                length_sig = int.from_bytes(conn.recv(4), "big")
                signature = conn.recv(length_sig)

                if plaintext.decode().lower() == "quit":
                    print("Client ended the chat.")
                    break

                print("Client says:", plaintext.decode())
                ok = verify_signature(plaintext, signature, client_cert_file)
                print("Signature:", "OK" if ok else "Failed")

                # Send reply
                reply = input("Server reply: ").encode()
                ciphertext_reply = rsa_encrypt(reply, "client_pub.pem")
                signature_reply = sign_message(reply)
                conn.sendall(len(ciphertext_reply).to_bytes(4, "big") + ciphertext_reply)
                conn.sendall(len(signature_reply).to_bytes(4, "big") + signature_reply)

                if reply.decode().lower() == "quit":
                    print("Server ended the chat.")
                    break
