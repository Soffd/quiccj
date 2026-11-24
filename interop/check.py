"""Run independent localhost HTTP/3 checks. Requires aioquic and the built h3get."""

import argparse
import asyncio
import re
import contextlib
import os
import hashlib
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
CLIENT = HERE.parent / "examples/h3get/target/release/bin/main"


def available_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.asynccontextmanager
async def server(directory, *flags):
    port = available_port()
    child = await asyncio.create_subprocess_exec(
        sys.executable, str(HERE / "server.py"), "--port", str(port), *flags,
        cwd=directory, stdout=asyncio.subprocess.PIPE,
    )
    try:
        ready = await asyncio.wait_for(child.stdout.readline(), 5)
        if not ready.startswith(b"HTTP/3 server listening"):
            raise RuntimeError("interop server failed to start")
        yield port
    finally:
        if child.returncode is None:
            child.terminate()
            await child.wait()


class LossProxy(asyncio.DatagramProtocol):
    """Drop two client datagrams and periodically drop or delay server datagrams."""

    def __init__(self, server_port):
        self.server = ("127.0.0.1", server_port)
        self.client = None
        self.client_initials = 0
        self.client_short = 0
        self.server_packets = 0
        self.dropped = 0
        self.delayed = 0

    def connection_made(self, transport):
        self.transport = transport

    def forward(self, data, peer):
        if not self.transport.is_closing():
            self.transport.sendto(data, peer)

    def datagram_received(self, data, peer):
        if peer == self.server:
            self.server_packets += 1
            if self.server_packets > 4 and self.server_packets % 19 == 0:
                self.dropped += 1
                return
            if self.server_packets > 4 and self.server_packets % 7 == 0:
                self.delayed += 1
                asyncio.get_running_loop().call_later(0.015, self.forward, data, self.client)
            else:
                self.transport.sendto(data, self.client)
            return
        self.client = peer
        if data[0] & 0x80:
            self.client_initials += 1
            if self.client_initials == 1:
                self.dropped += 1
                return
        else:
            self.client_short += 1
            if self.client_short == 4:
                self.dropped += 1
                return
        self.transport.sendto(data, self.server)


class RebindingProxy(asyncio.DatagramProtocol):
    """Stable client-facing address with two distinct, locally bound upstream UDP ports."""

    def __init__(self):
        self.client = None
        self.short_packets = 0
        self.upstreams = []
        self.switched = False

    def connection_made(self, transport):
        self.front = transport

    def datagram_received(self, data, addr):
        self.client = addr
        if not data[0] & 0x80:
            self.short_packets += 1
        self.switched = self.short_packets >= 5
        self.upstreams[int(self.switched)].sendto(data)

    def upstream(self):
        proxy = self

        class Upstream(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                proxy.front.sendto(data, proxy.client)

        return Upstream()


class DelayedPath(asyncio.DatagramProtocol):
    """A fixed-RTT path with an optional blackout during a multi-packet request."""

    def __init__(self, server_port, blackout):
        self.server = ("127.0.0.1", server_port)
        self.client = None
        self.blackout = blackout
        self.first_request_packet = None
        self.dropped = 0

    def connection_made(self, transport):
        self.transport = transport
        self.loop = asyncio.get_running_loop()

    def forward(self, data, peer):
        if not self.transport.is_closing():
            self.transport.sendto(data, peer)

    def datagram_received(self, data, peer):
        if peer == self.server:
            target = self.client
        else:
            self.client = peer
            target = self.server
            now = self.loop.time()
            if self.first_request_packet is None and not data[0] & 0x80 and len(data) > 900:
                self.first_request_packet = now
            if self.first_request_packet is not None and now - self.first_request_packet < self.blackout:
                self.dropped += 1
                return
        self.loop.call_later(0.020, self.forward, data, target)


async def check(client, backend):
    with tempfile.TemporaryDirectory(prefix="quiccj-") as tmp:
        directory = Path(tmp)
        for algorithm, key, cert, ca_flag in (
            ("ec", "key.pem", "cert.pem", False),
            ("rsa:2048", "rsa-key.pem", "rsa.pem", False),
            ("rsa:1024", "weak-key.pem", "weak.pem", False),
            ("ec", "ca-key.pem", "ca-leaf.pem", True),
        ):
            curve = ["-pkeyopt", "ec_paramgen_curve:prime256v1"] if algorithm == "ec" else []
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", algorithm, *curve,
                 "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj",
                 "/CN=localhost", "-addext", f"basicConstraints=critical,CA:{str(ca_flag).upper()}", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                cwd=directory, check=True, capture_output=True,
            )

        async def get(port, label, path="/", ca="cert.pem", *, repeat=1, mode="", code=0,
                      expected=(), recovery_check=None, env=None, default_backend=False):
            proc = await asyncio.create_subprocess_exec(
                str(client), "127.0.0.1", path, str(port), str(directory / ca),
                *([] if default_backend else [backend, str(repeat), mode]),
                env={**os.environ, **(env or {}), **({"QUICCJ_SEND_MTU": "1452"}
                    if mode == "transport" and sys.platform.startswith("linux") else {})},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            try:
                output, _ = await asyncio.wait_for(proc.communicate(), 25)
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
            result = output.decode()
            if proc.returncode != code or any(value not in result for value in expected):
                raise AssertionError(f"{label}: unexpected client result\n{result}")
            if recovery_check is not None:
                recovery_check(result)
            print(f"PASS {backend} {label}", flush=True)

        async with server(directory) as port:
            missing_library = {"QUICCJ_LIBCRYPTO": str(directory / "missing-library")}
            if backend == "openssl":
                await get(port, "default backend fails closed when OpenSSL is missing", env=missing_library,
                          default_backend=True, code=1, expected=("HTTP/3 GET", "OpenSSL 3 unavailable"))
            else:
                await get(port, "explicit software backend loads with OpenSSL absent", env=missing_library,
                          expected=("status: 200 complete=true",))
            await get(port, "verified GET and QPACK reuse", repeat=3,
                      expected=("status: 200 complete=true", "body bytes: 22", "qpack_known_received=1"))
            await get(port, "pooled alternative preserves authority and reuses the connection", mode="pool",
                      expected=("pool reused alternative with original authority",))
            def check_mtu(output):
                mtu = int(re.search(r"validated_mtu=(\d+)", output)[1])
                if sys.platform.startswith("linux") and mtu <= 1200:
                    raise AssertionError(f"no larger probe acknowledged (MTU {mtu})")
            await get(port, "QUIC DATAGRAM echo and path MTU probe", mode="transport",
                      expected=("datagram_echo_bytes=3",), recovery_check=check_mtu)
            pattern = bytes(range(251))
            digest = hashlib.sha256((pattern * (1048576 // len(pattern) + 1))[:1048576]).hexdigest()
            await get(port, "1 MiB POST with end-to-end digest", "/upload", mode="upload",
                      expected=("status: 200 complete=true", digest))
            await get(port, "streaming 1 MiB DATA", "/large", mode="stream",
                      expected=("status: 200 complete=true", "streamed bytes: 1048576", "body bytes: 0"))
            await get(port, "untrusted certificate rejected", ca="rsa.pem", code=1,
                      expected=("handshake=false", "certificate verification failed"))
            await get(port, "server push", "/push", mode="push",
                      expected=("status: 200 complete=true", "push bytes: 16"))
            await get(port, "GOAWAY", "/goaway", repeat=2, code=2,
                      expected=("complete=false rejected=true",))
            await get(port, "path migration", mode="migrate",
                      expected=("migrated=true", "status: 200 complete=true"))
            await get(port, "client key update", mode="key-update",
                      expected=("key_updated=true", "status: 200 complete=true"))
            await get(port, "0-RTT accepted", mode="resume",
                      expected=("resumed=true early_accepted=true complete=true status=200",))
            loop = asyncio.get_running_loop()
            rebinding = RebindingProxy()
            front, _ = await loop.create_datagram_endpoint(lambda: rebinding, local_addr=("127.0.0.1", 0))
            try:
                for _ in range(2):
                    upstream, _ = await loop.create_datagram_endpoint(rebinding.upstream, remote_addr=("127.0.0.1", port))
                    rebinding.upstreams.append(upstream)
                await get(front.get_extra_info("sockname")[1], "client NAT rebinding", "/large",
                          expected=("status: 200 complete=true", "body bytes: 1048576"))
                if not rebinding.switched:
                    raise AssertionError("client source port did not change")
            finally:
                for upstream in rebinding.upstreams:
                    upstream.close()
                front.close()
            proxy = LossProxy(port)
            transport, _ = await loop.create_datagram_endpoint(
                lambda: proxy, local_addr=("127.0.0.1", 0)
            )
            try:
                proxy_port = transport.get_extra_info("sockname")[1]
                await get(proxy_port, "1 MiB with datagram loss and reordering", "/large",
                          expected=("status: 200 complete=true", "body bytes: 1048576"))
                if proxy.dropped < 3 or proxy.delayed < 1:
                    raise AssertionError("loss / reordering injection did not run")
                print(f"     dropped {proxy.dropped}, delayed {proxy.delayed}", flush=True)
            finally:
                transport.close()
            path = "/" + "a" * 16000
            for blackout, label in (
                (0.0, "paced request on a 40 ms RTT path"),
                (1.4, "persistent congestion and recovery after a blackout"),
            ):
                proxy = DelayedPath(port, blackout)
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: proxy, local_addr=("127.0.0.1", 0)
                )
                try:
                    proxy_port = transport.get_extra_info("sockname")[1]
                    def check_recovery(result):
                        stats = re.search(r"pacing_deferrals=(\d+) persistent_congestion=(\d+)", result)
                        if not stats:
                            raise AssertionError(f"{label}: missing recovery counters")
                        paced, persistent = map(int, stats.groups())
                        if blackout:
                            if not proxy.dropped or not persistent:
                                raise AssertionError(f"{label}: dropped={proxy.dropped}, persistent={persistent}")
                        elif not paced or persistent:
                            raise AssertionError(f"{label}: pacing deferrals={paced}, persistent={persistent}")
                        print(f"     deferred {paced}, dropped {proxy.dropped}, persistent {persistent}", flush=True)

                    await get(proxy_port, label, path, expected=("status: 200 complete=true",),
                              recovery_check=check_recovery)
                finally:
                    transport.close()
        for label, cert, key in [("RSA-1024 rejected", "weak.pem", "weak-key.pem"),
                                 ("CA certificate rejected as TLS leaf", "ca-leaf.pem", "ca-key.pem")]:
            async with server(directory, "--cert", cert, "--key", key) as port:
                await get(port, label, ca=cert, code=1, expected=("certificate verification failed",))
        async with server(directory, "--reject-resumption") as port:
            await get(port, "0-RTT rejected and replayed as 1-RTT", mode="resume",
                      expected=("resumed=false early_accepted=false complete=true status=200",))
        async with server(directory, "--v2", "--retry") as port:
            await get(port, "v1 to v2 negotiation with Retry",
                      expected=("version=1798521807", "status: 200 complete=true"))
        async with server(directory, "--retry", "--chacha", "--key-update",
                          "--cert", "rsa.pem", "--key", "rsa-key.pem") as port:
            await get(port, "Retry, ChaCha20, RSA-PSS and peer key update", ca="rsa.pem",
                      expected=("status: 200 complete=true",))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", type=Path, default=CLIENT)
    parser.add_argument("--backend", choices=["pure", "openssl"], default="openssl")
    args = parser.parse_args()
    asyncio.run(check(args.client.resolve(), args.backend))
