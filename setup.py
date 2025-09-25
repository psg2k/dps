import subprocess
from pathlib import Path

def run(cmd):
    subprocess.run(cmd, check=True)

def setup_ca():
    # Create demoCA structure
    Path("demoCA/certs").mkdir(parents=True, exist_ok=True)
    Path("demoCA/crl").mkdir(exist_ok=True)
    Path("demoCA/newcerts").mkdir(exist_ok=True)
    Path("demoCA/private").mkdir(exist_ok=True)
    Path("demoCA/index.txt").write_text("")
    Path("demoCA/serial").write_text("1000")

    if not Path("ca.key").exists():
        run(["openssl", "genrsa", "-out", "ca.key", "4096"])
        run([
            "openssl", "req", "-new", "-x509", "-days", "3650",
            "-key", "ca.key", "-out", "ca.crt",
            "-subj", "/C=IN/ST=TN/L=Coimbatore/O=LabCA/OU=Root/CN=MyRootCA"
        ])
        print("Root CA created.")

def issue_cert(name):
    run(["openssl", "genrsa", "-out", f"{name}.key", "2048"])
    run([
        "openssl", "req", "-new", "-key", f"{name}.key", "-out", f"{name}.csr",
        "-subj", f"/C=IN/ST=TN/L=Coimbatore/O=Lab/OU={name}/CN={name}.local"
    ])
    run([
        "openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
        "-CAcreateserial", "-out", f"{name}.crt", "-days", "365"
    ])
    print(f"{name}.crt issued by CA.")

# Run setup directly
setup_ca()
issue_cert("server")
issue_cert("client")
