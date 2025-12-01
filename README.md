# 🛡️ Odysafe CTI Platform

![Logo Odysafe](cti-platform/static/images/logo-c.png)

## 🎯 Introduction

Odysafe CTI Platform is an on-premise solution to extract, organize, and enrich your IOCs (Indicators of Compromise).

It centralizes all your threat intelligence work in a simple web interface. You can import files, paste text, or manually enter IOCs. The platform automatically extracts them, organizes them with tags and groups, then exports them in various formats.

**Designed to be lightweight** 🚀

The application is built to be lightweight and run on minimal Linux servers without requiring extensive resources. Perfect for small teams or resource-constrained environments.

**Acknowledgments** 🙏

This solution integrates the remarkable work of several open-source projects:
- **[iocsearcher](https://github.com/malicialab/iocsearcher)** : for automatic IOC extraction from files
- **[deepdarkCTI](https://github.com/fastfire/deepdarkCTI)** : for access to CTI resources from the deep and dark web
- **[txt2stix](https://github.com/fastfire/txt2stix)** : for conversion to STIX 2.1 format

Thank you to all contributors of these projects! 🎉

---

## 🖥️ Web Interface

![IOCs Interface](docs/images/IOCs.png)

The web interface allows you to view, filter, and manage all your IOCs easily. You can tag them, group them, and export them with a few clicks.

---

## ✅ Features

| Feature | Available |
| --- | --- |
| Import files, URLs, or pasted text | ✅ |
| Manual IOC entry | ✅ |
| Automatic IOC extraction (iocsearcher) | ✅ |
| Tags, groups, and history | ✅ |
| Export TXT / CSV / JSON / STIX | ✅ |
| Authentication and session protection | ✅ |
| Background pipelines and cleanup | ✅ |
| Journald log rotation | ✅ |
| Push-based third-party CTI feeds | ✕ |
| Advanced workflow orchestration | ✕ |

---

## ⚡ Quick Install

### Prerequisites

**Compatible operating systems:**
- Debian
- Ubuntu
- RHEL / CentOS
- Rocky Linux
- AlmaLinux
- Fedora
- Amazon Linux

**Requirements:**
- Python 3.8 or higher
- 500 MB minimum disk space
- systemd
- git
- pip

### Installation

```bash
git clone https://github.com/Odysafe/ODYSAFE-CTI.git
cd ODYSAFE-CTI
./install.sh
```

The installation script automatically configures everything: dependencies, Python environment, systemd service, and SSL certificate.

![Installation](docs/images/install.gif)

Once installed, access the application:
- Local: `https://localhost:5001`
- Network: `https://<SERVER_IP>:5001`

---

## 📋 IOC Extraction

You can extract IOCs simply by pasting text into the interface. The platform automatically detects all IOC types present.

![IOC Extraction](docs/images/extractor.gif)

**Special thanks** 🙏

Automatic extraction is made possible thanks to **[iocsearcher](https://github.com/malicialab/iocsearcher)**, a powerful library that identifies IOCs in PDF, HTML, Word, and text files.

---

## 🌐 CTI Resources

The platform integrates access to CTI resources from the deep and dark web via the CTI Resources interface.

![CTI Resources](docs/images/CTI%20RESSOURCES.png)

You can browse hundreds of CTI sources organized by categories and add them directly to your platform.

**Special thanks** 🙏

This feature uses **[deepdarkCTI](https://github.com/fastfire/deepdarkCTI)**, a project that collects and shares Cyber Threat Intelligence resources from the deep and dark web. Thank you for this valuable work!

---

## 🧭 ISO 27001 Alignment

The platform complies with several ISO 27001 controls:

- **A.9 Access Control** : optional authentication, secured cookies, dedicated non-privileged service user
- **A.12 Operations** : automatic IOC workflows, log rotation, background cleanup, storage monitoring
- **A.14 System Acquisition & Development** : locally locked dependencies, import verification, configuration templates
- **A.16 Incident Management** : tagging system (False Positive, Investigating, Verified), report exports
- **A.18 Compliance** : SSL support, secret key management, log retention, documentation for audits

---

## 🔒 Privacy and Offline Operation

Odysafe CTI Platform operates offline by default. All processing, IOC extraction, tagging, and exports happen locally without sending information to external services.

### Internet Connections

The application connects to the Internet only in these specific cases:

1. **User-provided URL processing** : only when you explicitly provide a URL
2. **deepdarkCTI repository** : only when you click "Download" or "Update" in CTI Resources
3. **txt2stix external APIs** : optional, disabled by default, requires explicit configuration

### Data Privacy Guarantees

- All IOC data, sources, tags, and exports remain on your server
- No telemetry, analytics, or statistics are sent
- No automatic updates or background connections
- All processing (iocsearcher, txt2stix) runs locally
- The SQLite database and all files stay within your infrastructure

### Running Completely Offline

To operate in an air-gapped environment:

1. Skip the deepdarkCTI download during installation
2. Do not use the "Download" or "Update" buttons in CTI Resources
3. Do not use the URL import feature - use file upload or text paste instead
4. Do not configure txt2stix external APIs or AI extractors

All other features (IOC extraction from files, tagging, exports, authentication) work without an Internet connection.

---

## 📚 Logs and Observability

View application logs with these commands:

```bash
# View logs
sudo journalctl -u odysafe-cti-platform

# Follow logs in real-time
sudo journalctl -u odysafe-cti-platform -f

# Logs from the last hour
sudo journalctl -u odysafe-cti-platform --since "1 hour ago"

# Clean old logs
sudo journalctl --vacuum-time=7d
sudo journalctl --vacuum-size=100M
```

The journald configuration automatically limits log size (500 MB max, 30 days retention, daily rotation).

---

## 📝 License

GNU Affero General Public License v3.0 (AGPL-3.0)

See the `LICENSE` or `COPYING` files for more details.
