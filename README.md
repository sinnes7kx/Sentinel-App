# Sentinel

Local-first security assessment software for authorized websites, networks and software dependencies.

## Getting started

1. Open Sentinel from the Windows installer, or double-click `Start_Sentinel.bat` in a source checkout. The source launcher prepares a private Python environment automatically.
2. For basic website checks, enter your authorized website address in the main window. No external scanner is required.
3. To prepare optional tools, open **Tool setup** and choose the recommended setup. Sentinel detects existing components and prepares missing ones after your approval. Follow any Windows or vendor prompts and retry after a restart if needed.
4. In **Security tools**, select a check and use **Choose for me** to recommend an existing engine. Review the scope and permission before starting.

No separate Kali virtual machine is required for the managed Docker toolkit. Python environments and container images still use local disk space. ZAP preparation and report review are available, but desktop ZAP scanning and automatic Nikto installation are not yet implemented.

The product name is **Sentinel**. The existing application data directory, project history and runtime identifiers are unchanged.

## Local testing without GitHub Actions

In a complete Windows source checkout, close Sentinel and double-click `Test_Sentinel.bat`. The launcher uses the same private Python environment as Sentinel, compiles the source and runs the local unittest regression suite (including Tk GUI tests). It saves the console results to a timestamped text file in `%LOCALAPPDATA%\Sentinel\test-logs`. Share the failing test names and traceback when reporting a problem; review the log before sharing.

The first run may download the pinned Python dependencies if not already installed. Tests requiring OpenSSL can be skipped if it is missing; the launcher does not claim those checks passed. The full Docker integration lab and other operating system/Python combinations are not run by this launcher.

Cloud testing is now manual-only. Do not start the GitHub Actions Tests workflow unless you intend to consume your available Actions allowance.

## Windows offline installer (x64)

Run `Sentinel-Windows-x64.exe`, then open **Sentinel** from Start. The installer includes Python/Tk, the dependency and DNS libraries, Microsoft WSL, and a Kali filesystem containing **WhatWeb** and **sslscan**. The four summary cards and three-pane desktop show findings, actions, evidence and project history from your local assessments.

Open **Security tools**, choose **wsl** or **docker**, then **Prepare included tools**. Setup checks the local archive, registers it and remembers the verified environment. WhatWeb connects directly to the approved IP in WSL and Docker. Choose WhatWeb for an authorized IP URL or sslscan for a TLS endpoint. Choose a profile, confirm scope and select **Start**.

- **WSL 2** is the bundled path for x64 Windows 11 with hardware virtualization enabled. Initial setup can request Windows administrator approval for Virtual Machine Platform and the signed Microsoft WSL installer. If Windows requests a reboot, restart and select **Prepare included tools** again.
- **Docker** uses a running Linux-container engine on the same computer. Sentinel imports the included archive and runs its immutable local image ID. The Windows installer includes WSL for computers without a Docker engine.
- **Tool coverage** includes WhatWeb technology identification and sslscan protocol, cipher and certificate inspection. Nmap and Nikto remain separate integrations. Use an endpoint reachable from the selected runtime. Loopback in a container refers to that container.
- **Storage** is per user. The app lives under `%LOCALAPPDATA%\Programs\Sentinel`. Windows Settings can uninstall the desktop files. Assessment history and prepared WSL distributions or Docker images persist separately. The environment name or image ID appears in Security tools.
- **Build** on x64 Linux with Python 3.12+, Docker and NSIS 3.11+: `python3 packaging/windows/build.py dist/Sentinel-Windows-x64.exe`. Network access is used on the build machine. The Kali base is digest-pinned and apt verifies the rolling package index. The resulting installer includes the installed Debian package versions and archive checksum.

## Start Sentinel from source

On Windows, double-click `Start_Sentinel.bat` to open the desktop app. The launcher automatically creates a private Python virtual environment under `%LOCALAPPDATA%\\Sentinel\\python` and installs the pinned runtime requirements inside it. The first launch or a requirements change needs internet access; subsequent launches reuse the environment. No global pip installation or activation is needed. The equivalent managed command is `py -3 launch_private.py`. Direct `py -3 run.py` still uses the selected Python environment without automatic setup. The packaged Windows installer already includes its own Python and libraries. The app needs Python 3.10 or later with Tcl/Tk. If Tcl/Tk cannot start, the default launcher opens the local browser dashboard. Use `--desktop` to require the desktop, or `--web` to choose the browser directly.

The desktop workspace puts project history, findings, and evidence side by side. It also provides assessment comparison, HTML and JSON exports, dependency advisory checks, and existing external-tool configuration.

Open **Local utilities** for two offline workflows:

- **File integrity** streams a selected file and returns its SHA-256 and SHA-512 digests. Paste a trusted reference digest to see whether it matches.
- **Tool report review** summarizes saved ZAP JSON, Nmap XML, and Wireshark packet-list CSV files up to 5 MB.

Sentinel keeps these utility results in the window and does not add them to assessment history. Large files are hashed in chunks on the shared desktop worker.

## Browser dashboard

Sentinel runs locally with Python 3.10 or later. It opens your browser at a loopback address and saves website assessments to the local Sentinel database.

- **Windows** — Run `Start_Sentinel.bat --web` or `py -3 run.py --web` from the project folder.
- **Kali Linux** — Run `python3 run.py --web` from the project folder. Copy the printed address into your browser if it does not open automatically.

Enter the exact URL you have permission to check, confirm permission, and select **Run assessment**. Sentinel checks HTTPS, security headers, and cookies with a single request. Recent assessments can be reopened and exported as HTML or JSON. To add exact-domain DNS checks, install `dnspython` in the same Python environment and select **Also check DNS records**.

Under **Tool reports**, select and open an existing UTF-8 export up to 5 MB. The dashboard reads it locally and does not add it to assessment history.

| Tool | Accepted export | Dashboard summary |
|---|---|---|
| ZAP | [Traditional JSON](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/) | Sites and alert counts by reported severity |
| Nmap | [XML](https://nmap.org/book/output-formats-xml-output.html) | Hosts and explicitly listed and open ports |
| Wireshark | [Packet-list CSV](https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html) with the Protocol column | Packet count and most common protocols |

For the included practice page, run `py -3 demo_site.py` on Windows or `python3 demo_site.py` on Kali in a second terminal. Enter `http://127.0.0.1:8765/` in Sentinel. Press Ctrl+C in each terminal to stop its server.

## Desktop app

Run `py -3 run.py --desktop` on Windows or `python3 run.py --desktop` on Kali to require the desktop interface.

The Tkinter interface now shares one bounded background worker across website, external-tool and local dependency checks. Stop/cancel, timestamped progress events, redacted evidence, source/confidence fields and SQLite history are shared. Existing projects and adapters remain available.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the repository review, execution model, scope boundaries, backend setup and verification limits. Source checkouts default to the native backend. The offline installer opens Security tools with the bundled WSL option. Custom WSL/Docker environments must already contain the selected tool. WSL cancellation is experimental and may leave Linux work running until the profile timeout. Docker images must be locally available and selected by immutable ID or registry digest.

### Connect a separately managed Kali distribution

1. If Kali is missing, install it with `wsl --install --distribution kali-linux` from an administrator PowerShell. Restart Windows if prompted and finish the Kali user setup on first launch. [Kali WSL installation](https://www.kali.org/docs/wsl/wsl-preparations/)
2. In Sentinel, open **Security tools**, set **Run using** to **wsl**, and click **Detect distributions**. Sentinel prefers `kali-linux` when no listed distribution is already selected. You can also enter the exact name of a custom distribution.
3. Use **Check installed tools** to see whether Nmap, sslscan, WhatWeb, and their GNU `timeout` dependency are available. Choose a supported tool and use its normal profile and authorization controls.

The binaries run inside Kali under the distribution's configured user. Package installation is handled within Kali. Use an authorized address reachable from the distribution. A loopback address in Kali may refer to a different machine context from Windows loopback.

CI requires the GUI tests on Windows and Linux. Earlier version-specific test counts below are historical. The bundled tools completed local fixture checks in Linux Docker. Native Windows WSL and Docker Desktop setup and older 16 GB hardware performance remain unverified.

Sentinel is a local-first security assessment prototype for Windows, with a modular Python engine. Its long-term goal is a professional authorized penetration testing platform. This release is a working **configuration assessment**, not a complete penetration test, security certification, or production-ready security platform.

## Start the desktop app on Windows from source

1. Install Python 3.10 or later from https://www.python.org/downloads/windows/ (include Tcl/Tk and the Python launcher, which are normally included).
2. Extract the entire ZIP into a normal writable folder.
3. Run `py -3 run.py --desktop` in the extracted folder.
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
