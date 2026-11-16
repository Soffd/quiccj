"""Build an unsigned source snapshot for an independent reviewer."""

import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "examples/consumer_smoke/target/audit"
PROJECT_PATHS = (".gitignore", "LICENSE", "README.md", "docs", "examples", "interop", "quic", "quic_openssl")
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")


def git_files():
    command = ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *PROJECT_PATHS]
    entries = subprocess.check_output(command, cwd=ROOT).decode().split("\0")
    return sorted(set(filter(None, entries)))


def add_file(archive, name, data, mode=0o644):
    entry = tarfile.TarInfo(name)
    entry.mode = mode
    entry.size = len(data)
    archive.addfile(entry, io.BytesIO(data))


def bundle(output):
    memory = io.BytesIO()
    manifest = []
    with gzip.GzipFile(fileobj=memory, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as archive:
            for name in git_files():
                path = ROOT / name
                if path.is_symlink():
                    raise RuntimeError(f"review snapshot contains a symlink: {name}")
                if not path.exists():
                    continue  # allow a tracked deletion in the working tree
                if not path.resolve().is_relative_to(ROOT) or not path.is_file():
                    raise RuntimeError(f"unexpected review snapshot entry: {name}")
                if "\n" in name or "\r" in name or "\\" in name:
                    raise RuntimeError(f"unsupported checksum manifest path: {name!r}")
                data = path.read_bytes()
                if PRIVATE_KEY.search(data):
                    raise RuntimeError(f"review snapshot contains a PEM private key: {name}")
                manifest.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
                mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                add_file(archive, name, data, mode)
            add_file(archive, "SHA256SUMS", "".join(manifest).encode())
    data = memory.getvalue()
    checksum = hashlib.sha256(data).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    path = output / f"quiccj-review-{checksum[:12]}.tar.gz"
    path.write_bytes(data)
    path.with_suffix(path.suffix + ".sha256").write_text(f"{checksum}  {path.name}\n", encoding="ascii")
    print(f"{checksum}  {path.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    bundle(args.output_dir)
