import socket
import ssl
import hashlib

HOST = "127.0.0.1"
PORT = 65431

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations("ca.crt")

context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"[*] Secure mTLS server listening on {HOST}:{PORT}")

    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
        print(f"[+] Connection from {addr}")

        while True:
            data = conn.recv(1024)
            if not data:
                break

            hashed_msg = data.decode().strip()
            print(f"[Client hash]: {hashed_msg}")

            if hashed_msg.lower() in ("exit", "quit"):
                print("[*] Client requested to end session.")
                conn.sendall(b"Goodbye!")
                break

            # Server reply
            reply = input("[Server > ] ").strip()
            reply_hash = hashlib.sha256(reply.encode()).hexdigest()
            conn.sendall(reply_hash.encode())
            print(f"[*] Sent hash: {reply_hash}")

            if reply.lower() in ("exit", "quit"):
                print("[*] Server ending session.")
                break

        conn.close()
        print("[*] Connection closed.")
