"""Build a transferable ZIP from a committed Git revision, excluding local state."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
from zipfile import ZipFile, ZIP_DEFLATED


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT)


ROOT = Path(__file__).resolve().parents[1]


def main():
    commit = git("rev-parse", "HEAD").decode().strip()
    archive = git("archive", "--format=zip", "HEAD")
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    name = "custos-0.1.0-" + commit[:7] + ".zip"
    target = output / name
    total = 0
    with ZipFile(io.BytesIO(archive)) as source, ZipFile(target, "w", compression=ZIP_DEFLATED) as package:
        for entry in source.infolist():
            path = Path(entry.filename)
            if entry.is_dir() or path.parts[0] in {"dist", "releases", ".git", ".venv"}:
                continue
            if path.suffix.lower() in {".pem", ".key", ".db", ".sqlite", ".pyc"} or path.name.startswith(".env"):
                raise SystemExit(f"Refusing to package sensitive/local-state file: {entry.filename}")
            package.writestr("custos/" + entry.filename, source.read(entry))
            total += 1
        package.writestr("custos/RELEASE.json", json.dumps({"product": "Custos", "version": "0.1.0",
            "source_commit": commit, "source_files": total, "package_type": "Python source deployment bundle",
            "offline_dependencies_included": False, "vmware_licensed_assets_included": False}, indent=2))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    checksum = output / (name + ".sha256")
    checksum.write_text(digest + "  " + name + "\n", encoding="ascii")
    with ZipFile(target) as package:
        if package.testzip() is not None:
            raise SystemExit("ZIP verification failed")
        for required in ["TRANSFER.md", "pyproject.toml", "web/app.py", "src/custos/worker.py", "docs/setup-guide.md"]:
            package.getinfo("custos/" + required)
    print(json.dumps({"package": str(target), "checksum": str(checksum), "sha256": digest,
                      "bytes": target.stat().st_size, "source_commit": commit}, indent=2))


if __name__ == "__main__":
    main()
