# Network Requests Analysis

This document provides a complete analysis of all network requests made by Odysafe CTI Platform, when they occur, and the security measures in place.

## Overview

Odysafe CTI Platform is designed to operate offline by default. All network requests are either:
- Required during installation (dependencies, optional repositories)
- Explicitly triggered by user actions
- Optional and disabled by default

No automatic background connections, telemetry, analytics, or update checks are performed during normal operation.

## Network Requests During Installation

### 1. Network Connectivity Check

**When:** During installation, only if pip is not available in the system

**Destination:** `https://www.python.org`

**Method:** `curl` or `wget` connectivity test

**Purpose:** Verify network availability before attempting to download pip

**Security Measures:**
- Timeout: 5 seconds maximum
- Connect timeout: 3 seconds
- No data is sent, only connectivity verification
- Fails gracefully if network is unavailable

**Code Location:** `install.sh` lines 1272-1278

**User Control:** Automatic, only if pip is missing

---

### 2. Pip Installation (Fallback)

**When:** During installation, only if pip is not available and network connectivity is confirmed

**Destination:** `https://bootstrap.pypa.io/get-pip.py`

**Method:** `curl` or `wget` download, piped directly to Python

**Purpose:** Install pip as a fallback when system pip is unavailable

**Security Measures:**
- Timeout: 30 seconds maximum
- Connect timeout: 10 seconds
- Downloaded script is executed immediately without storage
- Only executed if network connectivity test succeeds
- Fails gracefully if download fails

**Code Location:** `install.sh` lines 1283, 1294

**User Control:** Automatic, only if pip is missing

---

### 3. Python Dependencies Installation

**When:** During installation

**Destination:** PyPI (Python Package Index) - `pypi.org`

**Method:** `pip install -r requirements.txt`

**Purpose:** Install required Python packages

**Packages Installed:**
- Flask==3.0.0
- Werkzeug==3.0.1
- requests>=2.31.0
- stix2>=3.0.0
- markdown>=3.4.0
- beautifulsoup4>=4.12.0
- python-magic>=0.4.27

**Security Measures:**
- Uses official PyPI repository
- Version pinning for critical packages (Flask, Werkzeug)
- Minimum version requirements for others
- All packages are open-source and publicly auditable
- Installed in isolated virtual environment

**Code Location:** `install.sh` (pip installation section)

**User Control:** Required for installation

---

### 4. GitHub Repository Cloning (Optional)

**When:** During installation, only if user accepts the prompt

**Destinations:**
- `https://github.com/fastfire/deepdarkCTI.git`
- `https://github.com/BushidoUK/Ransomware-Tool-Matrix.git`

**Method:** `git clone` via subprocess

**Purpose:** Download CTI resources repositories for offline use

**Security Measures:**
- User must explicitly accept during installation
- Can be skipped for air-gapped environments
- Repositories are cloned locally and used offline afterward
- No automatic updates after initial clone
- Timeout: 120 seconds maximum

**Code Location:** `install.sh` lines 1757, 1817

**User Control:** Optional, can be skipped

---

## Network Requests During Normal Operation

### 1. User-Provided URL Processing

**When:** When user explicitly submits a URL via the `/api/url` endpoint

**Destination:** User-provided URL (any HTTP/HTTPS URL)

**Method:** `requests.get()` with timeout

**Purpose:** Download content from user-provided URL to extract IOCs

**Security Measures:**
- Timeout: 30 seconds maximum
- User-Agent header: `Mozilla/5.0` (standard browser identification)
- Content is downloaded to temporary file
- Temporary file is deleted after processing
- Only executed when user explicitly provides a URL
- URL validation: must start with `http://` or `https://`

**Code Location:** `cti-platform/modules/iocsearcher_wrapper.py` line 247

**User Control:** Explicit user action required

---

### 2. CTI Resources Repository Download/Update (Manual)

**When:** When user clicks "Download" or "Update" button in CTI Resources interface

**Destinations:**
- `https://github.com/fastfire/deepdarkCTI.git`
- `https://github.com/BushidoUK/Ransomware-Tool-Matrix.git`

**Method:** `git clone` or `git pull` via subprocess

**Purpose:** Download or update CTI resources repositories

**Security Measures:**
- Only executed on explicit user action (button click)
- Git command timeout: 120 seconds
- Old repository is removed before cloning new one
- Cache is cleared before update
- Can be completely avoided by not using the feature

**Code Location:**
- `cti-platform/modules/github_repo.py` line 88
- `cti-platform/modules/github_repo_rtm.py` line 84
- Endpoints: `/api/cti-resources/download`, `/api/ransomware-tools/download`

**User Control:** Explicit user action required (button click)

---

### 3. Query URL Generation (No Actual Network Request)

**When:** When displaying IOC details in the interface

**Destinations:** URLs are generated but no HTTP request is made

**Purpose:** Generate clickable links for IOC lookup on external services (VirusTotal, URLhaus, etc.)

**Security Measures:**
- No network request is made by the application
- URLs are only displayed as clickable links
- User must manually click to visit external services
- No data is sent automatically

**Code Location:** `cti-platform/modules/ioc_query_urls.py`

**User Control:** User must manually click links to visit external sites

---

## Optional Network Features (Disabled by Default)

### txt2stix External APIs

**When:** Only if explicitly configured by user

**Destinations:** AI service APIs (OpenAI, Anthropic, Gemini, etc.)

**Method:** Via txt2stix library, if configured

**Purpose:** Enhanced IOC extraction using AI services

**Security Measures:**
- Disabled by default
- Requires explicit configuration via environment variables
- Environment variables are empty by default:
  - `CTIBUTLER_BASE_URL` (empty)
  - `VULMATCH_BASE_URL` (empty)
- No automatic activation
- User must explicitly configure API keys and endpoints

**Code Location:** `cti-platform/modules/txt2stix_wrapper.py` lines 216-218

**User Control:** Requires explicit configuration, disabled by default

---

## Internal API Calls (No Internet Connection)

### JavaScript Fetch Calls

**When:** During normal interface navigation

**Destinations:** Local server endpoints (`/api/*`)

**Method:** `fetch()` API calls to local Flask server

**Purpose:** Communication between web interface and backend

**Security Measures:**
- All requests are to localhost/server IP
- No external network connection
- Protected by authentication (if enabled)
- HTTPS/TLS when SSL is configured

**Code Location:** Various template files (HTML/JavaScript)

**User Control:** Automatic, internal only

---

## Security Measures Summary

### Network Request Controls

1. **No Automatic Background Requests:** The application never makes automatic background network requests during normal operation.

2. **Explicit User Actions:** All network requests (except installation) require explicit user actions:
   - User-provided URL processing
   - Manual repository download/update button clicks

3. **Timeouts:** All network requests have strict timeouts:
   - Connectivity checks: 5 seconds
   - File downloads: 30 seconds
   - Git operations: 120 seconds

4. **Graceful Failures:** All network operations fail gracefully if network is unavailable, allowing offline operation.

5. **Optional Features:** Network-dependent features are optional:
   - CTI repository downloads can be skipped
   - txt2stix AI features are disabled by default
   - URL processing is only used when explicitly requested

### Data Privacy

1. **No Telemetry:** No usage statistics, analytics, or telemetry data is sent.

2. **No Automatic Updates:** The application does not check for updates automatically.

3. **Local Processing:** All IOC extraction, tagging, and processing happens locally.

4. **Temporary Files:** Downloaded content is stored in temporary files and deleted after processing.

5. **Isolated Dependencies:** Python packages are installed in isolated virtual environment.

### Air-Gapped Operation

The platform can operate completely offline by:

1. Skipping CTI repository downloads during installation
2. Not using the URL import feature (use file upload or text paste instead)
3. Not clicking "Download" or "Update" buttons in CTI Resources
4. Not configuring txt2stix external APIs

All other features (IOC extraction from files, tagging, exports, authentication) work without any Internet connection.

---

## Network Request Summary Table

| Phase | Request Type | Destination | Trigger | User Control |
|-------|-------------|-------------|---------|--------------|
| Installation | Connectivity check | python.org | Automatic (if pip missing) | Required |
| Installation | Pip download | bootstrap.pypa.io | Automatic (if pip missing) | Required |
| Installation | Package installation | pypi.org | Automatic | Required |
| Installation | Repository clone | github.com | User prompt | Optional |
| Operation | URL processing | User-provided URL | User action | Explicit |
| Operation | Repository update | github.com | Button click | Explicit |
| Operation | Query URLs | None (generation only) | Display | Manual click |
| Operation | txt2stix APIs | AI services | Configuration | Optional, disabled |

---

## Conclusion

Odysafe CTI Platform is designed with privacy and offline operation as core principles. All network requests are either:

- Required for installation (dependencies)
- Explicitly triggered by user actions
- Optional and can be disabled

No automatic background connections, telemetry, or update checks are performed. The platform can operate completely offline for all core features.

