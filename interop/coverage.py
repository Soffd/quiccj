"""Run unit tests and enforce the production Cangjie source line-coverage floor."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "quic"


def main():
    # Isolate counters from earlier runs and stale packages in the source checkout.
    import shutil
    with tempfile.TemporaryDirectory(prefix="quiccj-coverage-") as tmp:
        project = Path(tmp) / "quic"
        shutil.copytree(ROOT, project, ignore=shutil.ignore_patterns(
            "target", ".cjpm", "cov_output", "*.gcno", "*.gcda"))
        subprocess.run(["cjpm", "test", "--coverage", "--no-color"], cwd=project, check=True)
        report = Path(tmp) / "report"
        subprocess.run(["cjcov", "-j", "-r", ".", "-s", "src", "-o", report], cwd=project, check=True)
        files = [f for f in json.loads((report / "coverage.json").read_text())["fileLists"]
                 if not f["filepath"].endswith("_test.cj")]
        lines = sum(f["totalLines"] for f in files)
        hit = sum(len(f["hitLines"]) for f in files)
        if not lines or hit * 100 < lines * 52:
            raise SystemExit(f"Production line coverage {hit}/{lines} below 52%")
        print(f"Production line coverage {hit}/{lines} ({100 * hit / lines:.2f}%)")


if __name__ == "__main__":
    main()
