"""Measure verified handshake latency and repeated GETs on a reusable connection."""
import argparse
import asyncio
from pathlib import Path
import re
import statistics
import subprocess
import tempfile
import time

from check import CLIENT, server


async def measure(args):
    with tempfile.TemporaryDirectory(prefix="quiccj-bench-") as tmp:
        root = Path(tmp)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", "key.pem", "-out", "cert.pem", "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "subjectAltName=IP:127.0.0.1"],
                       cwd=root, check=True, capture_output=True)
        async with server(root) as port:
            times = []
            requests = 0
            start = time.monotonic()
            async def worker():
                nonlocal requests
                while len(times) < args.samples or time.monotonic() - start < args.seconds:
                    run = await asyncio.create_subprocess_exec(
                        str(args.client), "127.0.0.1", "/", str(port), str(root / "cert.pem"), args.backend,
                        str(args.requests), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                    try:
                        output, _ = await asyncio.wait_for(run.communicate(), max(120, args.requests))
                    finally:
                        if run.returncode is None:
                            run.kill()
                            await run.wait()
                    text = output.decode()
                    expected = f"completed_requests={args.requests}" if args.requests > 1 else "status: 200 complete=true"
                    if run.returncode or expected not in text:
                        raise RuntimeError(text)
                    times.append(int(re.search(r"handshake=true elapsed_ms=(\d+)", text)[1]))
                    requests += args.requests

            await asyncio.gather(*(worker() for _ in range(args.concurrency)))
            print(f"{args.backend}: {len(times)} connections, {requests} verified GETs, "
                  f"handshake median {statistics.median(times)} ms, max {max(times)} ms, "
                  f"wall time {time.monotonic() - start:.1f} s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, default=CLIENT)
    parser.add_argument("--backend", choices=["pure", "openssl"], default="openssl")
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--requests", type=int, default=32)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--seconds", type=int, default=0, help="minimum run duration for soak testing")
    args = parser.parse_args()
    if min(args.samples, args.requests, args.concurrency) < 1 or args.seconds < 0:
        parser.error("positive sample and request counts required")
    asyncio.run(measure(args))
