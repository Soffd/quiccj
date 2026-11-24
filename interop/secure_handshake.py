"""Exercise verified HTTP/3 against nginx/OpenSSL 3.5 and optionally ngtcp2."""
import argparse
import datetime as dt
import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CLIENT = Path(__file__).resolve().parents[1] / "examples/h3get/target/release/bin/main"
PEM = serialization.Encoding.PEM


def make_pki(path):
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "interop CA")])

    def certificate(name, key, ca=False, usage=None):
        cert = (x509.CertificateBuilder().issuer_name(issuer).subject_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if usage:
            cert = cert.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        if usage == ExtendedKeyUsageOID.SERVER_AUTH:
            cert = cert.add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        return cert.sign(ca_key, hashes.SHA256(), rsa_padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=32))

    ca = certificate(issuer, ca_key, True)
    (path / "root.pem").write_bytes(ca.public_bytes(PEM))
    for name, key, usage in [
        ("server", ed25519.Ed25519PrivateKey.generate(), ExtendedKeyUsageOID.SERVER_AUTH),
        ("client", ec.generate_private_key(ec.SECP256R1()), ExtendedKeyUsageOID.CLIENT_AUTH),
    ]:
        cert = certificate(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]), key, usage=usage)
        (path / f"{name}.pem").write_bytes(cert.public_bytes(PEM))
        encoding = PEM if name == "server" else serialization.Encoding.DER
        (path / f"{name}.key").write_bytes(key.private_bytes(
            encoding, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        if name == "server":
            serial = cert.serial_number
            staple = (ocsp.OCSPResponseBuilder().add_response(
                cert, ca, hashes.SHA256(), ocsp.OCSPCertStatus.GOOD, now - dt.timedelta(minutes=1),
                now + dt.timedelta(hours=1), None, None).responder_id(ocsp.OCSPResponderEncoding.HASH, ca)
                .sign(ca_key, hashes.SHA256()))
            (path / "ocsp.der").write_bytes(staple.public_bytes(serialization.Encoding.DER))
    for filename in ["valid", "revoked", "stale"]:
        expires = now + dt.timedelta(days=-1 if filename == "stale" else 1)
        crl = (x509.CertificateRevocationListBuilder().issuer_name(issuer)
               .last_update(now - dt.timedelta(days=2)).next_update(expires))
        if filename == "revoked":
            crl = crl.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial)
                                              .revocation_date(now - dt.timedelta(hours=1)).build())
        (path / f"{filename}.crl").write_bytes(crl.sign(ca_key, hashes.SHA256()).public_bytes(PEM))


def run(client, nginx, ngtcp2, quiche):
    with tempfile.TemporaryDirectory(prefix="quiccj-auth-") as tmp:
        path = Path(tmp)
        make_pki(path)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        config = f"""daemon off;
master_process off;
pid {path}/pid;
events {{}}
http {{
    access_log off;
    client_body_temp_path {path}/body;
    proxy_temp_path {path}/proxy;
    fastcgi_temp_path {path}/fastcgi;
    uwsgi_temp_path {path}/uwsgi;
    scgi_temp_path {path}/scgi;
    server {{
        listen 127.0.0.1:{port} quic;
        ssl_certificate {path}/server.pem;
        ssl_certificate_key {path}/server.key;
        ssl_client_certificate {path}/root.pem;
        ssl_verify_client on;
        ssl_ecdh_curve X25519MLKEM768;
        ssl_stapling on;
        ssl_stapling_file {path}/ocsp.der;
        ssl_trusted_certificate {path}/root.pem;
        location / {{ return 200 "$ssl_client_verify $ssl_curve"; }}
    }}
}}
"""
        (path / "nginx.conf").write_text(config)
        args = [str(client), "127.0.0.1", "/", str(port), str(path / "root.pem")]

        def check(label, *, identity=True, crl="valid", success=True, expected="", backend="openssl", staple=False):
            env = os.environ.copy()
            if staple:
                env["QUICCJ_REQUIRE_OCSP"] = "1"
            if identity:
                env.update(QUICCJ_CLIENT_CHAIN=str(path / "client.pem"), QUICCJ_CLIENT_KEY_DER=str(path / "client.key"))
            env["QUICCJ_CRL_FILE"] = str(path / f"{crl}.crl")
            result = subprocess.run([*args, backend], capture_output=True, text=True, timeout=15, env=env)
            if (result.returncode == 0) != success or expected not in result.stdout:
                raise AssertionError(f"{label}: {result.stdout}{result.stderr}")
            print(f"PASS {label}", flush=True)

        with subprocess.Popen([nginx, "-p", tmp, "-c", str(path / "nginx.conf")]) as server:
            try:
                time.sleep(0.2)
                if server.poll() is not None:
                    raise RuntimeError("nginx failed to start")
                check("mTLS, Ed25519, RSA-PSS chain, fresh CRL and hybrid-only group", expected="SUCCESS")
                check("signed OCSP staple", staple=True, expected="SUCCESS")
                check("revoked leaf", crl="revoked", success=False, expected="certificate verification failed")
                check("expired CRL", crl="stale", success=False, expected="certificate verification failed")
                check("mandatory client certificate", identity=False, success=False)
            finally:
                server.terminate()
        if ngtcp2:
            (path / "index.html").write_text("ngtcp2 interop")
            with subprocess.Popen([ngtcp2, "-q", "-d", tmp, "127.0.0.1", str(port),
                                   path / "server.key", path / "server.pem"]) as server:
                try:
                    time.sleep(0.2)
                    if server.poll() is not None:
                        raise RuntimeError("ngtcp2 failed to start")
                    check("required OCSP staple missing", identity=False, staple=True, success=False,
                          expected="certificate verification failed")
                    for backend in ("openssl", "pure"):
                        check(f"ngtcp2 {backend} verified GET", identity=False, expected="ngtcp2 interop", backend=backend)
                        check(f"ngtcp2 {backend} revoked leaf", identity=False, success=False,
                              crl="revoked", expected="certificate verification failed", backend=backend)
                finally:
                    server.terminate()

        if quiche:
            (path / "index.html").write_text("quiche interop")
            with subprocess.Popen([quiche, "--listen", f"127.0.0.1:{port}", "--cert", path / "server.pem",
                                   "--key", path / "server.key", "--root", tmp]) as server:
                try:
                    time.sleep(0.2)
                    if server.poll() is not None:
                        raise RuntimeError("quiche failed to start")
                    check("quiche verified GET", identity=False, expected="quiche interop")
                finally:
                    server.terminate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, default=CLIENT)
    parser.add_argument("--nginx", default="nginx")
    parser.add_argument("--ngtcp2")
    parser.add_argument("--quiche")
    args = parser.parse_args()
    run(args.client.resolve(), args.nginx, args.ngtcp2, args.quiche)
