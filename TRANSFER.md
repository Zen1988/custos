# Transfer and install Custos

This repository is the complete Python web application, worker and console broker.
The `web/` directory alone is not a standalone installation package.

## Get the package

- Download the [GitHub ZIP](https://github.com/Zen1988/custos/archive/refs/heads/main.zip), then extract it.
- Or build a commit-specific bundle with `python scripts/package_release.py` from a Git checkout.
  This creates `dist/custos-0.1.0-<commit>.zip` and its `.sha256` checksum. It packages
  committed files only; commit intended changes before building.

The bundle includes the app, worker, templates/styles, noVNC client and licenses,
tests, deployment examples and full setup guide. It excludes `.git`, virtual
environments, databases, private keys and local secrets.

## Transfer to Linux

Copy the ZIP and checksum to the destination server using your approved transfer
method. For example, from a machine with OpenSSH:

```bash
scp custos-0.1.0-<commit>.zip custos-0.1.0-<commit>.zip.sha256 admin@custos-host:/tmp/
```

On the Linux server:

```bash
cd /tmp
sha256sum -c custos-0.1.0-<commit>.zip.sha256
sudo apt update
sudo apt install -y unzip python3 python3-venv
unzip custos-0.1.0-<commit>.zip
cd custos
python3 -m venv .venv
.venv/bin/python -m pip install '.[postgres,console]'
```

Do not include the literal `<commit>` placeholder in commands; use the downloaded
filename. For GitHub's automatic ZIP, use its extracted directory name instead.
These `/tmp` commands are a transfer/install check, not the permanent service layout.
Follow **docs/setup-guide.md** to install under `/opt/custos`, configure PostgreSQL,
separate RBAC credentials/keys, systemd, HTTPS proxy and backend integrations.
Then use `https://your-custos-host/admin/setup-guide` for the portal version.

## Requirements not inside the ZIP

- Python 3.11+, PostgreSQL and nginx/Apache are installed on the destination.
- Python packages are downloaded by pip during installation. For an air-gapped
  server, prepare an approved wheelhouse matching that server's Linux architecture
  and Python version first. Windows virtual environments/wheels are not a Linux bundle.
- Supply deployment secrets, TLS certificates and backend/AD accounts separately.
- VMware's licensed WebMKS browser assets must be obtained separately. Nutanix
  console API/version/session authentication requirements still apply.
- This is a source deployment bundle, not a preconfigured appliance, offline
  installer or claim of completed live-provider acceptance.
