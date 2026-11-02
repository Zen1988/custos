"""Install the official pinned noVNC source assets, retaining license notices."""
import hashlib
import io
import json
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile

URL = "https://github.com/novnc/noVNC/archive/refs/tags/v1.6.0.zip"
destination = (Path(__file__).resolve().parents[1] / "web/static/vendor/novnc").resolve()
with urlopen(URL, timeout=30) as response:
    blob = response.read(20 * 1024 * 1024)
digest = hashlib.sha256(blob).hexdigest()
manifest = destination / "SOURCE.json"
if manifest.exists() and json.loads(manifest.read_text())["sha256"] != digest:
    raise SystemExit("Source archive hash changed; verify the upstream release before updating")
with ZipFile(io.BytesIO(blob)) as archive:
    for member in archive.infolist():
        parts = Path(member.filename).parts[1:]
        if not parts or member.is_dir():
            continue
        if parts[0] not in {"core", "vendor"} and not (len(parts) == 1 and parts[0].startswith(("LICENSE", "COPYING", "AUTHORS"))):
            continue
        target = destination.joinpath(*parts).resolve()
        if not target.is_relative_to(destination):
            raise SystemExit("Unsafe archive path")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.read(member))
manifest.write_text(json.dumps({"url": URL, "version": "1.6.0", "sha256": digest}, indent=2))
print("Installed official noVNC 1.6.0 assets with source manifest and license notices")
