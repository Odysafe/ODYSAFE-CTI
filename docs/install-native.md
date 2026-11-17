# Native installation

Clone the repository:

```bash
git clone https://github.com/Odysafe/ODYSAFE-CTI.git
cd ODYSAFE-CTI
```

ODYSAFE provides a standard installation path and an optional service-management path.

## Standard installation

Make the installer executable:

```bash
chmod +x install.sh
```

Run it:

```bash
./install.sh
```

Then start ODYSAFE on the loopback interface:

```bash
chmod +x start.sh
CTI_HOST=127.0.0.1 ./start.sh
```

By default, ODYSAFE uses port `5001`.

When HTTPS is enabled:

```text
https://localhost:5001
```

---

## Optional service mode

The service script is **not mandatory**.

It is useful when you want ODYSAFE to run as a managed service instead of launching it manually with `./start.sh`.

Make the script executable:

```bash
chmod +x scripts/install-service.sh
```

Then install the service:

```bash
./scripts/install-service.sh install
```

The script automatically detects the available service mechanism:

- **systemd** on supported Debian/Ubuntu hosts;
- **SysV / service** in environments where systemd is unavailable, including compatible containers.

The service script expects the ODYSAFE Python environment to already exist. If `venv/` has not yet been created, run `./install.sh` first.

Manage the service with:

```bash
./scripts/install-service.sh status
./scripts/install-service.sh restart
./scripts/install-service.sh logs
./scripts/install-service.sh remove
```

On SysV-compatible environments, the generated service can also be controlled with:

```bash
service odysafe-cti start
service odysafe-cti stop
service odysafe-cti restart
service odysafe-cti status
```

---

## Requirements

Recommended environment:

- Linux
- Python 3.10+
- `pip`
- `git`
- `openssl`
- `libmagic`

The standard installer prepares the Python environment, dependencies, runtime directories, TLS material and optional CTI datasets. Provision Python dependencies and any datasets before disconnecting the host. The Docker archive is the ready-to-run offline installation for Linux x86-64. [Docker quick start](../README.md#quick-start)

Normal startup supports explicit URL imports and updates for Data-Shield, DeepDarkCTI, Ransomware Tool Matrix and MITRE ATT&CK. Use `CTI_HOST=127.0.0.1 CTI_ALLOW_REMOTE=0 ./start.sh` to disable these actions. Native execution relies on the host firewall for network isolation.

---

## Main Local Data Paths

Runtime data is stored under the local installation directory, including:

```text
cti-platform/database/
cti-platform/uploads/
cti-platform/outputs/iocs/
cti-platform/outputs/stix/
cti-platform/outputs/reports/
cti-platform/data/zettelforge/
cti-platform/ssl/
```

Operational databases, generated certificates, analyst notes, uploaded intelligence, reports, logs, backups, caches, and other runtime data should not be committed to the public repository.

### Offline Dataset Placement

When ODYSAFE is deployed without internet access, place optional datasets at these paths before restarting the platform:

```text
docs/enterprise-attack.json
cti-platform/modules/deepdarkCTI-main/
cti-platform/modules/Ransomware-Tool-Matrix-main/
cti-platform/modules/data_shield/prod_data-shield_ipv4_blocklist.txt
cti-platform/modules/cache/
```

- `docs/enterprise-attack.json`: MITRE ATT&CK Enterprise STIX JSON bundle.
- `cti-platform/modules/deepdarkCTI-main/`: local clone or copy of `fastfire/deepdarkCTI`.
- `cti-platform/modules/Ransomware-Tool-Matrix-main/`: local clone or copy of `BushidoUK/Ransomware-Tool-Matrix`.
- `cti-platform/modules/data_shield/prod_data-shield_ipv4_blocklist.txt`: Data-Shield IPv4 blocklist text file.
- `cti-platform/modules/cache/`: local cache, favorites, manual source files, and deleted source metadata.

To use CTI Memory offline, extract the optional data pack and point `FASTEMBED_CACHE_PATH` at its `model-cache/` directory. Use an absolute path and preserve the cache symlinks when copying it.

```sh
FASTEMBED_CACHE_PATH=/absolute/path/odysafe-cti-data/model-cache CTI_HOST=127.0.0.1 ./start.sh
```

On a connected native staging machine, `CTI_ALLOW_MODEL_DOWNLOAD=1` authorizes initial model acquisition when Memory is used. Omit that setting for offline use.

---
