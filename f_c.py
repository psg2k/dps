import socket
import ssl

HOST = "127.0.0.1"
PORT = 65431a


context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="client.crt", keyfile="client.key")
context.load_verify_locations("ca.crt")
context.check_hostname = False

context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print(f"[*] Connected securely with mTLS to {HOST}:{PORT}")

        while True:
            msg = input("[Client > ] ").strip()
            ssock.sendall(msg.encode())
            print(ssock.cipher())


            if msg.lower() in ("exit", "quit"):
                print("[*] Client ending session.")
                break

            data = ssock.recv(1024)
            if not data:
                break
            reply = data.decode().strip()
            print(f"[Server]: {reply}")

            if reply.lower() in ("exit", "quit", "goodbye!"):
                print("[*] Server ended the session.")
                break
