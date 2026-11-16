"""Build fresh out-of-tree consumers and exercise QUIC/HTTP/3 and the C ABI."""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "interop"))
from check import server

RUNTIME_HEADER = (
    "https://raw.githubusercontent.com/cangjielanguage/cangjie_runtime/"
    "8e6100a28cddadc91174b89900dadcb8626624f6/runtime/src/Cangjie.h"
)
HEADER_HASH = "644244e3806a48846cf3489112092e17f262159db3acb0c069adbdfac748cd38"
EXPECTED_BODY = b"hello from aioquic h3\n"


def run(command, *, cwd=None, env=None, timeout=120):
    result = subprocess.run(
        [str(arg) for arg in command], cwd=cwd, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise RuntimeError(result.stdout.decode(errors="replace"))
    return result.stdout


def build_consumer(kind, scratch):
    project = scratch / kind
    shutil.copytree(HERE / kind, project, ignore=shutil.ignore_patterns("target", ".cjpm", "cjpm.lock"))
    manifest = project / "cjpm.toml"
    text = manifest.read_text(encoding="utf-8")
    for dependency in ("quic", "quic_openssl"):
        text = text.replace(f'"../../../{dependency}"', json.dumps(str(REPO / dependency)))
    manifest.write_text(text, encoding="utf-8")
    run(["cjpm", "build"], cwd=project)
    return project


def runtime_library():
    search = [
        Path(path) for path in os.environ.get("LD_LIBRARY_PATH", "").split(os.pathsep) if path
    ]
    if sdk := os.environ.get("CANGJIE_HOME"):
        search.append(Path(sdk) / "runtime/lib" / f"linux_{platform.machine()}_cjnative")
    for directory in search:
        if (directory / "libcangjie-runtime.so").is_file():
            return directory.resolve()
    raise RuntimeError("Cangjie runtime not found. Load the Cangjie 1.2.1 SDK environment.")


def build_native(scratch, header):
    project = build_consumer("native", scratch)
    if header is None:
        with urllib.request.urlopen(RUNTIME_HEADER, timeout=20) as response:
            data = response.read(128 * 1024)
        if hashlib.sha256(data).hexdigest() != HEADER_HASH:
            raise RuntimeError("Cangjie runtime header checksum mismatch")
    else:
        data = header.read_bytes()
    (project / "Cangjie.h").write_bytes(data)

    runtime = runtime_library()
    host = scratch / "native-host"
    run([
        "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong",
        project / "smoke.c", f"-L{runtime}", "-lcangjie-runtime", "-o", host,
    ])
    env = os.environ.copy()
    paths = [str(runtime), env.get("LD_LIBRARY_PATH", "")]
    env["LD_LIBRARY_PATH"] = os.pathsep.join(filter(None, paths))
    bridge = project / "target/release/consumer_native/libconsumer_native.so"
    return host, bridge, env


def certificate(directory, cert, key):
    run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], cwd=directory)


async def smoke(header, direct_only):
    with tempfile.TemporaryDirectory(prefix="quiccj-consumer-") as tmp:
        scratch = Path(tmp)
        direct = build_consumer("direct", scratch) / "target/release/bin/main"
        native = None if direct_only else build_native(scratch, header)
        ca = scratch / "cert.pem"
        other_ca = scratch / "other.pem"
        certificate(scratch, ca, "key.pem")
        certificate(scratch, other_ca, "other-key.pem")

        async with server(scratch) as port:
            args = [direct, "127.0.0.1", port, ca]
            stdout = await asyncio.to_thread(run, args, cwd=scratch, timeout=25)
            if stdout != b"status=200\n" + EXPECTED_BODY:
                raise AssertionError(f"unexpected direct consumer response: {stdout!r}")
            args[-1] = other_ca
            rejected = await asyncio.to_thread(
                subprocess.run, [str(arg) for arg in args], cwd=scratch, timeout=25,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            if rejected.returncode != 1 or b"handshake failed" not in rejected.stdout:
                raise AssertionError(f"unexpected wrong-CA result: {rejected.stdout!r}")
            print("Cangjie path dependency: status=200, body=22, wrong CA rejected", flush=True)

            if native is not None:
                host, bridge, env = native
                output = await asyncio.to_thread(
                    run, [host, bridge, port, ca, other_ca], cwd=scratch, env=env, timeout=55,
                )
                print(output.decode(), end="")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-header", type=Path, help="use a local Cangjie 1.2.1 Cangjie.h")
    parser.add_argument("--direct-only", action="store_true", help="test only the pure-Cangjie consumer")
    args = parser.parse_args()
    asyncio.run(smoke(args.runtime_header, args.direct_only))
