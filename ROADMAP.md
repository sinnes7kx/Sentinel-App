# Sentinel product roadmap

Goal: a trusted, evidence-driven authorized penetration testing product that reduces the time between identifying an issue and demonstrating a verified fix. Competing with established security tools requires independent validation, reliable coverage, customer feedback and continuous maintenance; not just adding scan modules.

## Release sequence

The current v0.5 development work prioritizes the shared execution architecture over the earlier AI proposal below. AI remains optional future work and is not required to run Sentinel.

1. **Current foundation:** preserve Tkinter and existing adapters; one bounded scheduler, cancellation/events, authorization before resolution, checked-address Nmap/sslscan execution, standardized confidence/source, common redaction, offline dependency history, structured metadata logs and optional explicit execution backends.
2. **Before a professional beta:** Windows Job Objects/process-tree termination; cancel-safe WSL supervision; strict IP egress enforcement for hostname-based web tools; durable job journal and restart recovery; real third-party binaries against local fixtures; native Windows installer/signing; memory/CPU/latency benchmarks on older 16 GB machines. Require zero off-scope requests in rebinding/redirect tests and independent review.
3. **Next adapters:** start with offline Gitleaks, then Semgrep and OSV/Trivy inventory imports. Require license review, real-version fixtures, bounded local directory scope, secret-redacted evidence and clear unknown coverage. Add ZAP only with explicit scoped contexts and a local test application. Do not install an entire Kali distribution for each user.
4. **Later specialized modules:** WPScan, Nikto expansion and TLS tooling only with measured request budgets and scope controls. Lynis through isolated Linux backends. Greenbone and packet-capture workflows need separate resource and privilege design; do not enable them by default on 16 GB Windows systems.

Each milestone must ship functioning checks and measured verification, rather than disabled buttons or simulated vulnerability findings. The original release intentions below are retained as historical context.

- v0.1 (included): single-URL low-impact configuration assessment, projects, evidence, remediation, history and reports.
- v0.2: coverage reporting, hardened scope/authorization policy, cancellation/deadlines, local TLS test harness, DNS/email configuration checks, Windows usability and packaging.
- v0.3: software inventory and versioned, attributable vulnerability intelligence. Distinguish exact affected versions from uncertain matches. License review before integrating third-party engines or databases.
- v0.4: authorized web assessment orchestration with defined scope, per-target request budgets, explicit ownership/permission workflows and controlled local test fixtures.
- v0.5: optional AI explanations grounded in sanitized evidence; no unrestricted command execution. Prevent target-controlled content from becoming AI instructions. Keep sensitive data local by default.
- v0.6+: Pro research and development: authenticated testing with dedicated test accounts, API contract/authorization regression tests, supervised staging-based impact validation, network configuration review, risk correlation, evidence and remediation verification. Require explicit approved scope, rate limits, test windows, cancellation, audit logging and non-destructive defaults. Never treat payment as authorization.
- Business: multi-project/team workflows, scheduled authorized assessments, access control, reporting and governance. Payment/licensing after product stability and security validation.

## Release gates

Each check needs positive/negative fixtures, deterministic evidence, known limitations, versioned coverage, safe failure handling and remediation guidance. Active assessments need independently reviewed scope enforcement and controls. Track false positives and false negatives using known ground truth. No arbitrary security scores or fabricated severity claims. No claim of complete penetration testing or guaranteed security.

## Evaluation

Measure finding precision, known-fixture detection coverage, time to remediation, scope violations (target: zero), regression rates and repeatability. Start with a small set of consenting pilot users and staging targets before broader distribution. Seek independent security review before commercial deployment.
