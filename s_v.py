import socket
import ssl

HOST = "127.0.0.1"
PORT = 65431

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations("ca.crt")

votes = [0, 0, 0]  # For 3 contestants

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"[*] Secure Voting Server listening on {HOST}:{PORT}")

    with context.wrap_socket(sock, server_side=True) as ssock:
        # Accept 3 clients
        for i in range(3):
            conn, addr = ssock.accept()
            print(f"[+] Voter {i+1} connected from {addr}")

            vote = conn.recv(1024).decode().strip()
            print(f"[Voter {i+1}] Voted: {vote}")

            # Parse vote like "1 0 0"
            parts = vote.split()
            if len(parts) == 3:
                for idx, val in enumerate(parts):
                    if val == "1":
                        votes[idx] += 1

            conn.sendall(b"Vote recorded. Thank you!")
            conn.close()

        # After 3 votes, announce winner
        print("\n=== Voting Finished ===")
        print("Votes:", votes)

        winner = votes.index(max(votes)) + 1
        result = f"Candidate {winner} wins with {max(votes)} votes!"

        print(result)