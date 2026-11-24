# Sentinel v0.5 development — assessment architecture

The Tkinter interface now shares one bounded background worker across website, external-tool and local dependency checks. Stop/cancel, timestamped progress events, redacted evidence, source/confidence fields and SQLite history are shared. Existing projects and adapters remain available.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the repository review, execution model, scope boundaries, backend setup and verification limits. Native Windows is the default. Optional WSL/Docker modes in **Security tools** require an installed environment and supported tool; no automatic installs or image downloads occur. WSL cancellation is experimental and may leave Linux work running until the profile timeout. Docker images must be locally available and digest-pinned.

Local verification of this revision: 114 tests discovered, 111 passed, three skipped because this environment lacks working Tk/Tcl and OpenSSL. CI requires the GUI tests on Windows and Linux. Earlier version-specific test counts below are historical. Live WSL/Docker execution and older 16 GB hardware performance remain unverified.

Sentinel is a local-first security assessment prototype for Windows, with a modular Python engine. Its long-term goal is a professional authorized penetration testing platform. This release is a working **configuration assessment**, not a complete penetration test, security certification, or production-ready security platform.

## Start on Windows

1. Install Python 3.10 or later from https://www.python.org/downloads/windows/ (include Tcl/Tk and the Python launcher, which are normally included).
2. Extract the entire ZIP into a normal writable folder.
3. Double-click `Start_Sentinel.bat`. Alternatively, run `py -3 run.py` in the extracted folder.
4. Enter a project name and an exact HTTP or HTTPS URL you own or have explicit permission to assess. Confirm authorization, then select Run assessment.
5. Select observations for evidence and remediation. Export a standalone HTML report. Run the same URL again after a fix, then use Compare previous scan.

No GPU, mandatory pip dependencies, API key, payment or AI service required for web assessment. Optional DNS checks require dnspython; double-click Install_Optional_DNS.bat to install it. The UI uses Python's built-in Tkinter instead of PySide6 for this first lightweight release. Python 3.10+ is the intended compatibility range; the included tests were executed with Python 3.13 on Linux. The Windows GUI has not been interactively tested. See RELEASE_NOTES.md for v0.2 changes and limitations.

## What it actually checks

- One GET request to the exact entered URL; no automatic redirects or discovery of other pages.
- Standard TLS certificate and hostname verification; negotiated TLS version and certificate expiry when available. No protocol or cipher enumeration.
- HTTPS/HSTS indicators; selected browser-security headers on successful HTML responses.
- Cookie attribute observations (without retaining cookie names or values); technology-identification header presence.
- Explicit partial/failed status when a check cannot be completed.
- Local SQLite projects/history, comparison of observed finding IDs, HTML reporting.

Observations are contextual configuration indicators, not confirmed exploits. Cookie purposes and application behavior are unknown. The scanner does not validate CSP effectiveness, test authenticated workflows or establish security coverage. A finding no longer observed on a comparable response is not proof of remediation. The UI requires permission attestation each run; this is not technical proof of ownership. Only test authorized systems within their agreed scope. A GET can cause state changes on incorrectly designed applications, so prefer a staging page. The Stop button cooperatively cancels between operations; it does not interrupt a blocked socket call. Socket timeout is not a hard wall-clock deadline; DNS and other operations can extend runtime. The app does not persist HTTP bodies, raw response headers, cookie values or redirect locations. It does persist the target URL and derived findings. Do not enter sensitive tokens in paths. Local SQLite storage is not encrypted by Sentinel; protect the OS user account, exports and backups accordingly.

## Try the included local test page

In a terminal in the extracted folder, run `py -3 demo_site.py`, then open Sentinel separately and assess `http://127.0.0.1:8765/` or `http://127.0.0.1:8765/fixed`. Both are synthetic local-only pages; stop the fixture using Ctrl+C. Compare repeated assessments of the same exact URL. The demo's /fixed path has several more headers, but is still HTTP and not an example of a completely secure production site.

## Tests

`py -3 -m unittest discover -s tests -v`

Tests use local loopback HTTP fixtures, pure header analysis and temporary SQLite databases. No public website is contacted. 23 unit/integration tests passed in the build environment, including local verified and untrusted HTTPS fixtures (requires OpenSSL for that test). DNS tests use a mock resolver. The GUI initialized under a Linux virtual display. Native Windows GUI, live DNS, performance, production safety and independent security audit remain unverified.

## Data location

Windows: `%LOCALAPPDATA%\Sentinel\sentinel.sqlite3`. Other platforms: `~/.local/share/Sentinel/sentinel.sqlite3` unless LOCALAPPDATA is set. Close Sentinel before copying the database for backups. Delete this file after closing Sentinel if you want to remove all locally stored history. Exports are separate files.

## Architecture

- `sentinel/engine.py`: normalized URL, explicit authorization gate, bounded socket operations, header analysis, structured observations, retest comparisons.
- `sentinel/store.py`: local project/history persistence.
- `sentinel/report.py`: escaped static HTML reporting.
- `sentinel/app.py`: desktop UI; a background thread performs a single assessment without blocking the main event loop.
- `tests/`: repeatable local validation.

See ROADMAP.md for the intended product direction. Paid modules, AI, payments, automatic online vulnerability feeds, exploitation and automatic fixes are **not implemented**. Optional external-tool checks and local advisory matching are available as described below.

## v0.2 optional DNS and CLI

Enter an exact approved mail domain in the optional DNS field and attest permission for both targets. The domain may differ from the website host; do not enter a domain outside your authorized scope. The system-configured DNS resolver receives four logical queries (TXT at the domain and _dmarc, MX and CAA at the domain). No automatic DNS domain discovery occurs. Raw TXT content is not stored. No DKIM or inherited-policy evaluation is included. Install optional dnspython using the included batch file.

For local command-line use: `py -3 -m sentinel http://127.0.0.1:8765/ --authorized --json-out report.json --html-out report.html` (start the included demo first). Exit 0 indicates completed assessment, not a secure target. Exit 2 indicates incomplete assessment or invalid invocation. The CLI does not write project history.

v0.2 extends passive response analysis with additional browser headers, cookie attributes, CORS indicators and negotiated TLS metadata. It retains the exact-URL/no-redirect boundary. Reports contain coverage and assessment profile. The existing SQLite data remains readable; v0.1 findings cannot be compared directly with v0.2 because coverage changed.

## v0.4 (in development): integrated security tools

Open **Security tools…** in the header. One window runs every integrated check and saves results to the project history and reports:

| Check | Tool | Needs |
|---|---|---|
| Website checkup (recommended) | Sentinel built-ins + the three web tools below, whichever are installed | nothing extra |
| Network port scan | Nmap | `sudo apt install nmap` |
| Technology fingerprint | WhatWeb | `sudo apt install whatweb` |
| TLS and certificate check | sslscan | `sudo apt install sslscan` |
| Web server misconfiguration | Nikto (non-attacking test groups only) | `sudo apt install nikto` |

Architecture: `sentinel/tools/base.py` runs every tool the same way (scope check, authorization, no shell, time and output limits, untrusted-output parsing). A new tool is one file defining a `ToolSpec` (profiles, argument builder, parser) plus one line in `tools/__init__.py`. Private/loopback targets need the permission checkbox; any other target must also be typed back and is limited to one host. Nikto severities are keyword estimates and are labeled as such. Parsers were written against documented output formats and fixtures; validate them against real tool output on Kali before relying on them. Tests: `py -3 -m unittest discover -s tests -v`.
