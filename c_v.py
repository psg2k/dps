import socket
import ssl

HOST = "127.0.0.1"
PORT = 65431

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="client.crt", keyfile="client.key")
context.load_verify_locations("ca.crt")
context.check_hostname = False

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print(f"[*] Connected securely with mTLS to {HOST}:{PORT}")

        # Take vote input
        print("Enter your vote (example: '1 0 0' or '0 1 0' or '0 0 1')")
        vote = input("[Vote] > ").strip()

        ssock.sendall(vote.encode())
        print("[*] Vote sent securely!")

        # Wait for result from server
        result = ssock.recv(1024).decode().strip()
        print(f"[Server Result]: {result}")