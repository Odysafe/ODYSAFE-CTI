# 🛡️ Odysafe CTI Platform

![Logo Odysafe](cti-platform/static/images/logo-c.png)

## 🎯 Introduction

Odysafe CTI Platform is an on-premise solution to extract, organize, and enrich your IOCs (Indicators of Compromise).

It centralizes all your threat intelligence work in a simple web interface. You can import files, paste text, or manually enter IOCs. The platform automatically extracts them, organizes them with tags and groups, then exports them in various formats.

**Designed to be lightweight** 🚀

The application is specifically designed to be lightweight and function efficiently on minimal Linux servers without requiring extensive resources. It uses a SQLite database, runs with minimal memory footprint, and processes data locally without heavy external dependencies. Perfect for small teams or resource-constrained environments where performance and simplicity are key priorities.

**External Resources and Tools** 🔧

This platform uses the following open-source tools and resources as dependencies:
- **[iocsearcher](https://github.com/malicialab/iocsearcher)** : used for automatic IOC extraction from files
- **[deepdarkCTI](https://github.com/fastfire/deepdarkCTI)** : used as a source of CTI resources from the deep and dark web
- **[txt2stix](https://github.com/fastfire/txt2stix)** : used for conversion to STIX 2.1 format
- **[pdfalyzer](https://github.com/michelcrypt4d4mus/pdfalyzer)** : used for PDF analysis with colors and YARA rules
- **[Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix)** : used as a source of comprehensive ransomware tools, groups and community reports

These tools and resources are integrated into the platform to provide their respective functionalities.

Odysafe CTI Platform thanks the developers and maintainers of these open-source projects for making their tools and resources available to the community.

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
| Export formats: TXT, TXT simple, CSV, CSV firewall, JSON, JSON simple, XLSX, STIX 2.1 | ✅ |
| Authentication and session protection | ✅ |
| Background pipelines and cleanup | ✅ |
| Journald log rotation | ✅ |
| PDF analysis with YARA rules and structure visualization | ✅ |
| CTI Resources browsing (DeepDarkCTI, Ransomware Tool Matrix) | ✅ |
| Source management and favorites | ✅ |
| Bulk operations (delete, tag, group) | ✅ |
| Storage monitoring and cleanup | ✅ |
| Push-based third-party CTI feeds | ✕ |
| Advanced workflow orchestration | ✕ |

## 🎯 Key Capabilities

| Daily Need | Solution | Status |
|------------|----------|--------|
| **Store identified CTI resources** | Centralized SQLite database with source management and favorites | ✅ |
| **Quickly classify IOCs with TLP** | Built-in TLP tagging (RED, AMBER, GREEN, WHITE, CLEAR) | ✅ |
| **Extract IOCs from DFIR reports** | Automatic extraction from PDF, Word, HTML, text files via iocsearcher | ✅ |
| **Organize IOCs by threat type** | Tagging system (Malware, Phishing, APT, C2, etc.) and custom groups | ✅ |
| **Track IOC validation status** | Status tags (Verified, False Positive, Under Investigation) | ✅ |
| **Export to security tools** | Multi-format export: TXT, TXT simple, CSV, CSV firewall, JSON, JSON simple, XLSX, STIX 2.1 | ✅ |
| **Browse CTI sources** | Integrated access to DeepDarkCTI and Ransomware Tool Matrix with favorites | ✅ |
| **Analyze suspicious PDFs** | YARA-based detection, PDF structure visualization, and binary search via pdfalyzer | ✅ |
| **Filter and search IOCs** | Advanced filtering by type, date, tags, groups, and text search | ✅ |
| **Bulk operations** | Bulk delete, bulk tag assignment, bulk group assignment for IOCs and sources | ✅ |
| **Maintain audit trail** | Complete history with first_seen, last_seen, and source tracking | ✅ |
| **Storage management** | Automatic cleanup, storage monitoring, and manual cleanup tools | ✅ |

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

![IOC Extraction](docs/images/extractor--paste-url.gif)

**IOC Extraction**

Automatic IOC extraction is powered by **[iocsearcher](https://github.com/malicialab/iocsearcher)**, a library integrated into this platform that identifies IOCs in PDF, HTML, Word, and text files.

PDF analysis features use **[pdfalyzer](https://github.com/michelcrypt4d4mus/pdfalyzer)**, a tool integrated into this platform that enables in-depth visualization of PDF tree structures and scanning for potentially malicious content using YARA rules.

Odysafe CTI Platform thanks the iocsearcher and pdfalyzer projects for providing these valuable tools.

---

## 🌐 CTI Resources

The platform integrates access to CTI resources from the deep and dark web via the CTI Resources interface.

![CTI Resources](docs/images/CTIRESSOURCES.gif)

You can browse hundreds of CTI sources organized by categories and add them directly to your platform. The interface provides access to two main resources:

- **DeepDarkCTI** : Collection of cyber threat intelligence sources from the Deep and Dark Web
- **Ransomware Tool Matrix** : Comprehensive resources on tools, groups and community reports related to ransomware

**CTI Resources**

This feature integrates:
- **[deepdarkCTI](https://github.com/fastfire/deepdarkCTI)**, an open-source resource that collects and shares Cyber Threat Intelligence sources from the deep and dark web
- **[Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix)**, an open-source resource that documents the tools used by ransomware gangs

These resources are integrated into the platform to provide access to CTI sources and ransomware intelligence.

Odysafe CTI Platform thanks the deepdarkCTI and Ransomware Tool Matrix projects for making these valuable resources available.

---

## 🏠 Home Interface

The home page provides a central dashboard for accessing all platform features.

![Home Interface](docs/images/home.gif)

---

## 📊 Export Functionality

Export your IOCs in various formats:

- **TXT** : Text format with IOC types
- **TXT Simple** : Values only, compatible with firewalls and EDR systems
- **CSV** : Detailed format with metadata (tags, groups, dates, sources)
- **CSV Firewall** : Simplified format compatible with firewalls and EDR systems
- **JSON** : Complete internal format with all metadata
- **JSON Simple** : Simplified format grouped by IOC type
- **XLSX** : Excel format with formatted report and color coding
- **STIX 2.1** : Standard threat intelligence format via txt2stix

Exports can be filtered by sources, groups, IOC types, and date ranges.

![Export to Excel](docs/images/exportxlsx.gif)

---

## 📄 PDF Analysis

Analyze suspicious PDF files with YARA-based detection and visualize PDF structure.

![PDF Analysis](docs/images/pdfanalysis.gif)

---

## 🧭 ISO 27001 & NIS2 Compliance

**ISO 27001:2022 Controls:**
- **A.9 Access Control**: Optional authentication, secured cookies, dedicated service user
- **A.12 Operations**: Automatic IOC workflows, log rotation, background cleanup, storage monitoring
- **A.14 System Acquisition & Development**: Locked dependencies, import verification, configuration templates
- **A.16 Incident Management**: Tagging system (False Positive, Investigating, Verified), report exports
- **A.18 Compliance**: SSL support, secret key management, log retention, audit documentation

**NIS2 Directive Alignment:**
- **Article 21 - Cybersecurity measures**: Centralized IOC management, threat classification, full traceability
- **Incident management**: IOC tracking and classification (True Positive, False Positive, Verified)
- **Threat intelligence**: Centralized IOC enrichment for rapid threat response
- **Reporting**: Structured exports (STIX 2.1) for threat information sharing
- **Operational resilience**: Offline operation, storage monitoring, secure data handling

---

## 🔒 Privacy and Offline Operation

Odysafe CTI Platform operates offline by default. All processing, IOC extraction, tagging, and exports happen locally without sending information to external services.

### Internet Connections

The application connects to the Internet only in these specific cases:

1. **User-provided URL processing** : only when you explicitly provide a URL
2. **CTI Resources repositories** : only when you click "Download" or "Update" in CTI Resources (DeepDarkCTI and Ransomware Tool Matrix)
3. **txt2stix external APIs** : optional, disabled by default, requires explicit configuration

### Data Privacy Guarantees

- All IOC data, sources, tags, and exports remain on your server
- No telemetry, analytics, or statistics are sent
- No automatic updates or background connections
- All processing (iocsearcher, txt2stix) runs locally
- The SQLite database and all files stay within your infrastructure

### Running Completely Offline

To operate in an air-gapped environment:

1. Skip the CTI Resources repositories download during installation
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

## 🚀 Roadmap

The following features are planned for future releases:

- **Automatic IOC enrichment** for malicious indicators
- **Multi-source correlation** to identify relationships between IOCs
- **YARA and Sigma rules management** for detection rule creation, optimization, and correction

These enhancements will further strengthen the platform's capabilities in threat intelligence analysis and detection rule management.

---

## 📝 License

GNU Affero General Public License v3.0 (AGPL-3.0)

See the `LICENSE` or `COPYING` files for more details.
