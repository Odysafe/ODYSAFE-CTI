# 🛡️ Odysafe CTI Platform

![Logo Odysafe](static/images/logo-c.png)

Odysafe CTI Platform is an on-premise intelligence workbench that centralizes IOC extraction, enrichment, tagging, and export from every format analysts encounter. It bundles vetted local versions of `iocsearcher` and `txt2stix`, Flask templates, and automation designed for SOC/SIRT workflows.

## ✅ What the platform actually covers

| Capability | Included |
| --- | --- |
| File, URL, or paste ingestion | ✅ |
| Manual IOC entry | ✅ |
| Automatic IOC extraction (iocsearcher) | ✅ |
| Tagging, grouping, and note history | ✅ |
| Export to TXT / CSV / JSON / STIX | ✅ |
| Authentication and session protection | ✅ |
| Background pipelines and cleanup | ✅ |
| Journald log rotation | ✅ |
| Push-based third-party CTI feeds | ✕ |
| Workflow orchestration beyond exports | ✕ |

Table keeps the scope factual; no attempt is made to position the project as a full CTI program beyond the listed features.

## 📚 Table of contents

1. [Daily usage](#-what-teams-do-with-it-every-day)
2. [Typical scenarios](#-daily-scenarios-worth-mentioning)
3. [ISO 27001 alignment](#-iso-27001-alignment)
4. [Privacy and offline operation](#-privacy-and-offline-operation)
5. [Quick install](#-quick-install-steps)
6. [Security checklist and logs](#-security-checklist)
7. [Verification & adjustments](#-installation-verification)
8. [Contributing and thanks](#-contributions)

## 🌟 What teams do with it every day

- Intake files, URLs, logs, or pasted text and let the pipeline validate them with extension and MIME checks before indexing.
- Apply tags, groups, and notes on IOCs so investigations stay contextual, traceable, and shareable.
- Export curated feeds as TXT, CSV, JSON, or STIX 2.1 to feed other tools, partners, or reporting dashboards.
- Monitor progress tasks, storage, and cleanup status through the dashboard and API endpoints.
- Rotate old sources automatically and keep journald logs under control with the installer-provided configuration.

## 📋 Daily scenarios worth mentioning

- Triage analysts upload a PDF, the extractor finds 42 IOC types, and the team quickly marks some as TLP:AMBER and exports a STIX bundle for partners.
- Threat hunters paste OSINT content, apply custom groups (APT, phishing), and distribute CSV lists to automation scripts.
- SOC leadership watches `/status` APIs, checks short-term metrics, and triggers manual cleanup when storage approaches limits.
- Integrators pull `/api/export/stix` to push structured reports into a SOAR playbook.
- Support uses `/api/settings/cleanup/uploads` and `/api/settings/cleanup/outputs` to remove temporary files before snapshots.

## 🧭 ISO 27001 alignment

- A.9 Access Control: optional authentication, session cookies secured, dedicated non-privileged service user, and database user management.
- A.12 Operations: automatic IOC workflows, journald rotation script, background cleanup threads, storage monitoring, and progresstracking.
- A.14 System Acquisition & Development: installer locks dependencies (iocsearcher/txt2stix locally), verifies imports, and ships with configuration templates.
- A.16 Incident Management: tagging system (False Positive, Investigating, Verified), report exports, and `/api/generate-complete-report` for threat sharing.
- A.18 Compliance: SSL support, secret key guidance, journald retention, and documentation to ease audits.

## 🔒 Privacy and offline operation

Odysafe CTI Platform is designed to operate offline by default. All data processing, IOC extraction, tagging, and exports happen locally without sending any information to external services.

### Internet connectivity

The application makes internet connections only in these specific cases:

1. **User-provided URL processing** (`/api/url` endpoint):
   - **When**: Only when you explicitly provide a URL to extract IOCs from
   - **What**: Downloads the content of the URL you specify (HTML, PDF, TXT, etc.)
   - **Data sent**: Standard HTTP GET request to your specified URL
   - **Data received**: Content of the webpage/document for IOC extraction
   - **Note**: The URL is provided by you, not automatically accessed

2. **deepdarkCTI repository** (optional):
   - **When**: Only when you click "Download" or "Update" in the CTI Resources section
   - **What**: Clones `https://github.com/fastfire/deepdarkCTI.git` to provide access to CTI resources
   - **Data sent**: Standard git clone request (no IOC data, no user information, no analytics)
   - **Data received**: Public markdown files containing CTI source references and metadata

3. **txt2stix external APIs** (optional, disabled by default):
   - **When**: Only if you configure `CTIBUTLER_BASE_URL` or `VULMATCH_BASE_URL` environment variables
   - **When**: Only if you configure AI extractor API keys (OpenAI, Anthropic, Gemini, etc.)
   - **Status**: Not used by default in the application
   - **Note**: These features require explicit configuration and are not active out of the box

### Data privacy guarantees

- All IOC data, sources, tags, notes, and exports remain on your server
- No telemetry, analytics, or usage statistics are sent anywhere
- No automatic updates or background connections
- All processing (iocsearcher, txt2stix) runs locally using bundled dependencies
- The SQLite database and all uploaded files stay within your infrastructure

### Running completely offline

If you need to operate in a fully air-gapped environment:

1. Skip the deepdarkCTI download during installation (the installer will warn but continue)
2. Do not use the "Download" or "Update" buttons in the CTI Resources section
3. Do not use the URL import feature (`/api/url` endpoint) - use file upload or paste instead
4. Do not configure txt2stix external APIs or AI extractors
5. All other features (IOC extraction from files, tagging, exports, authentication) work without any internet connection

This design ensures maximum confidentiality for sensitive threat intelligence operations.

## ⚙️ Quick install steps

```bash
tar -xzf odysafe-odysafe-cti-platform-op.tar.gz
cd op
sudo ./install.sh
```

The installer:
- installs prerequisites (Python 3.8+, pip, git, libmagic, etc.)
- builds a virtualenv, installs requirements, and configures local `iocsearcher` + `txt2stix`
- creates the service user `odysafe-cti-platform` and directories under `/opt/odysafe-cti-platform`
- copies the journald rotation config `journald-cti-platform.conf` and restarts `systemd-journald`
- registers the systemd service, starts it, and verifies Flask/iocsearcher/txt2stix imports

Access:

- Local: `http://localhost:5001`
- Remote: `http://<SERVER_IP>:5001`

## 🔐 Security checklist

- Set a strong `CTI_SECRET_KEY` via environment variable before going to prod.
- Keep `CTI_DEBUG=false` so unexpected tracebacks stay internal.
- Enable SSL with `CTI_USE_SSL=true` or place the service behind an HTTPS reverse proxy.
- Limit firewall exposure to the CTI port (default 5001) or route through a VPN.
- Maintain journald retention (500 MB total, 30 days, daily rotation, compression).
- Use the cleanup endpoints to trim uploads and outputs regularly.

## 📚 Logs and observability

```bash
sudo journalctl -u odysafe-cti-platform
sudo journalctl -u odysafe-cti-platform -f
sudo journalctl -u odysafe-cti-platform --since "1 hour ago"
sudo journalctl --vacuum-time=7d
sudo journalctl --vacuum-size=100M
```

## 🧪 Installation verification

- The installer runs Python checks to confirm Flask, `iocsearcher`, and `txt2stix` import correctly before finishing.
- Use the systemd service status and journal commands if something stops unexpectedly.

## 🛠️ Manual adjustments

- Configure cleanup, auto-rotation, and limits through `/api/settings/*` or the SQLite helpers.
- Reinstallations keep uploads, outputs, and the database intact thanks to the installer preserving those directories.
- You can adjust environment variables by editing a systemd override file (`sudo systemctl edit odysafe-cti-platform`).

## 🤝 Contributions

- Fork, branch from `main`, and describe how your changes impact installation, exports, or logging.
- Include validation steps or tests for uploads, exports, or authentication flows.
- Open a pull request with a concise summary and note any manual configuration required.

## 📝 License

GNU Affero General Public License v3.0 (AGPL-3.0). See `LICENSE` or `COPYING`.

## 🎉 Thanks

Gratitude to the open-source communities behind iocsearcher, txt2stix, and deepdarkCTI for powering the intelligence pipelines behind Odysafe CTI Platform.
