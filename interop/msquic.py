"""Run the native Windows client against a loopback Kestrel / MsQuic HTTP/3 server."""
import argparse
import base64
from collections import deque
import hashlib
import queue
import threading
import time
import datetime as dt
import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def reference_clients(port, root, cert, chrome, firefox, firefox_executable, nss_certutil, curl):
    url = f"https://127.0.0.1:{port}/"
    if curl:
        result = subprocess.run([curl, "--noproxy", "*", "--http3-only", "--cacert", root / "cert.pem",
                                 "--fail", "--silent", "--show-error", "-w", " %{http_version}", url],
                                capture_output=True, text=True, timeout=20)
        if result.returncode or result.stdout != "MsQuic HTTP/3 3":
            raise RuntimeError(result.stdout + result.stderr)
        print("PASS curl reference / Kestrel HTTP/3", flush=True)
    if not (chrome or firefox):
        return
    from playwright.sync_api import sync_playwright
    with sync_playwright() as browsers:
        if chrome:
            encoded = cert.public_key().public_bytes(serialization.Encoding.DER,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo)
            pin = base64.b64encode(hashlib.sha256(encoded).digest()).decode()
            browser = browsers.chromium.launch(executable_path=chrome, args=["--enable-quic",
                f"--origin-to-force-quic-on=127.0.0.1:{port}", f"--ignore-certificate-errors-spki-list={pin}",
                "--no-proxy-server"])
            try:
                page = browser.new_page()
                page.goto(url, timeout=15000)
                if page.locator("body").inner_text() != "MsQuic HTTP/3":
                    raise RuntimeError("Chrome did not use HTTP/3")
                print("PASS Chrome reference / Kestrel HTTP/3", flush=True)
            finally:
                browser.close()
        if firefox:
            profile = root / "firefox-profile"
            profile.mkdir()
            database = "sql:" + profile.name
            subprocess.run([nss_certutil, "-N", "-d", database, "--empty-password"], check=True, cwd=root)
            subprocess.run([nss_certutil, "-A", "-d", database, "-n", "quiccj reference CA", "-t", "C,,",
                            "-i", "cert.pem"], check=True, cwd=root)
            context = browsers.firefox.launch_persistent_context(profile, executable_path=firefox_executable,
                firefox_user_prefs={"network.http.http3.enable": True, "network.proxy.type": 0,
                    "network.http.http3.disable_when_third_party_roots_found": False,
                    "network.dns.disableIPv6": True,
                    "network.http.http3.alt-svc-mapping-for-testing": f"localhost;h3=:{port}"})
            try:
                page = context.new_page()
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    navigation = page.goto(f"https://localhost:{port}/?request={time.monotonic_ns()}", timeout=10000)
                    if page.locator("body").inner_text() == "MsQuic HTTP/3":
                        print("PASS Firefox reference / Kestrel HTTP/3", flush=True)
                        break
                    time.sleep(0.25)
                else:
                    protocol = page.evaluate("performance.getEntriesByType('navigation')[0].nextHopProtocol")
                    raise RuntimeError(f"Firefox returned {navigation.status} over {protocol}")
            finally:
                context.close()


def check(client, chrome, firefox, firefox_executable, nss_certutil, curl):
    with tempfile.TemporaryDirectory(prefix="quiccj-msquic-") as temp:
        root = Path(temp)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = dt.datetime.now(dt.timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "quiccj local test CA")])
        ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
              .not_valid_after(now + dt.timedelta(days=1)).add_extension(x509.BasicConstraints(True, 0), True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
              .sign(ca_key, hashes.SHA256()))
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
                .not_valid_after(now + dt.timedelta(days=1)).add_extension(x509.BasicConstraints(False, None), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                                           x509.DNSName("localhost")]), False)
                .sign(ca_key, hashes.SHA256()))
        (root / "cert.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (root / "cert.pfx").write_bytes(pkcs12.serialize_key_and_certificates(
            b"localhost", key, cert, None, serialization.BestAvailableEncryption(b"local-test")))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]

        (root / "Test.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
            '<ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>')
        (root / "Program.cs").write_text(f"""
using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, {port}, endpoint => {{
    endpoint.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
    endpoint.UseHttps("cert.pfx", "local-test");
}}));
var app = builder.Build();
app.MapGet("/", (HttpContext context) => {{
    context.Response.Headers["Alt-Svc"] = "h3=\\\":{port}\\\"; ma=60";
    return "MsQuic " + context.Request.Protocol;
}});
app.Run();
""")
        env = dict(os.environ, DOTNET_NOLOGO="1", DOTNET_CLI_TELEMETRY_OPTOUT="1",
                   DOTNET_GENERATE_ASPNET_CERTIFICATE="false")
        subprocess.run(["dotnet", "build", "-v:q"], cwd=root, check=True, env=env, timeout=120)
        with subprocess.Popen(["dotnet", root / "bin/Debug/net8.0/Test.dll"], cwd=root, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, env=env) as server:
            try:
                ready = queue.Queue()
                recent = deque(maxlen=20)
                def watch():
                    for line in server.stdout:
                        recent.append(line.rstrip())
                        if "Application started" in line:
                            ready.put(True)
                    ready.put(False)
                threading.Thread(target=watch, daemon=True).start()
                if not ready.get(timeout=15):
                    raise RuntimeError("Kestrel failed to start")
                for backend in ("openssl", "pure"):
                    result = subprocess.run([client, "127.0.0.1", "/", str(port), root / "cert.pem", backend],
                                            capture_output=True, text=True, timeout=20)
                    if result.returncode or "MsQuic HTTP/3" not in result.stdout:
                        raise RuntimeError(result.stdout + result.stderr)
                    print(f"PASS Windows {backend} / Kestrel MsQuic GET", flush=True)
                reference_clients(port, root, cert, chrome, firefox, firefox_executable, nss_certutil, curl)
            except Exception:
                print("\n".join(recent), flush=True)
                raise
            finally:
                server.terminate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--chrome", help="Chrome executable for reference-client comparison")
    parser.add_argument("--firefox", action="store_true", help="use Playwright Firefox as a reference client")
    parser.add_argument("--firefox-executable", help="alternate Playwright Firefox executable")
    parser.add_argument("--nss-certutil", default="certutil", help="Mozilla NSS certutil for the temporary Firefox profile")
    parser.add_argument("--curl", help="HTTP/3-enabled curl executable")
    args = parser.parse_args()
    check(args.client.resolve(), args.chrome, args.firefox or args.firefox_executable, args.firefox_executable, args.nss_certutil, args.curl)
