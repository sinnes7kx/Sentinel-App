# Sentinel assessment architecture

## Review baseline and decisions

Reviewed the tracked source, tests, fixtures, launch scripts, workflow and documentation at main commit `a9dcbc412f5b0d12134d24e825031dae2309b883` before editing. Existing compiled bytecode is not a source of truth and is preserved, not imported into the change. The repository already contains Nmap, WhatWeb, sslscan, Nikto, a website suite and offline Python dependency intelligence. No earlier ZIP import is needed and no private databases, reports or credentials are imported.

Keep Python and Tkinter: the existing single-request HTTP/TLS checks, optional DNS posture, reports, comparison, SQLite projects and tool parsers are useful foundations. Replacing the UI would add migration risk without improving assessment correctness. The most pressing review findings were independent unbounded window workers, DNS resolution before attestation, missing shared redaction, discarded subprocess exit codes and silent output limits. Those paths are changed here. This is a development foundation, not a claim of production certification or comprehensive pentesting.

## Components and data flow

`Tk windows -> Orchestrator -> built-in check / ToolSpec / offline assessor -> sanitized result -> UI-thread SQLite save -> history / report`

* `orchestration.py`: one application worker and at most four waiting jobs. Each job has a unique ID, cancellation event, current state and timestamped queued/running/terminal events. UI polls state; events do not invent a percentage. Completion callbacks only enqueue data; workers never access Tk or a UI-owned SQLite connection. Completed jobs leave the live registry.
* `tools/base.py`: adapters declare fixed profiles, target kind, permitted schemes, executable candidates, argument builder and parser. Shared execution checks authorization before DNS, validates scope, locates the program, runs with deadlines, parses output, and records coverage. Unknown profiles fail closed. No user-supplied command flags.
* `tools/runner.py`: argument arrays with `shell=False`, hidden Windows console, separate drained stdout/stderr pipes, 16 MB per-stream retention and an explicit truncation flag. Cancellation/timeout terminates the direct process, escalates to kill and reaps it. Detached descendants are not guaranteed to terminate; Windows Job Objects and process-tree isolation remain a release gate.
* `tools/backends.py`: native default; explicit optional WSL distribution or immutable local Docker image. Scan execution never installs packages or pulls images. The Windows installer supplies native sslscan and WhatWeb plus a private Ruby runtime. Older releases with a Kali archive can still use their provisioning code. Optional backends support Nmap, sslscan and WhatWeb individually; the suite and Nikto remain native.
* `engine.py`: backwards-compatible `Scan` and `Finding` records. Findings carry ID, severity, title, evidence, remediation, confidence and source. Existing records remain readable. Severity expresses potential impact; confidence expresses evidence strength. Nmap port heuristics and Nikto keyword classifications use low confidence, other current observations default to medium. No CVSS score or high confidence is invented.
* `evidence.py`: recursive redaction of common secret keys, authorization/cookie headers, key material, URL credentials and common secret assignments. Individual text fields are capped at 32 KiB. This is best effort, not a guarantee that arbitrary secrets are recognized. Review exported evidence before sharing.
* `store.py`: existing projects/scans schema retained. Additional metadata and lifecycle events live in the scan JSON, so no destructive migration is required. Both writes and reads sanitize evidence; old database bytes are not rewritten. Offline matches are normalized by `dependency_result.py`, with the inventory hash as target and no private filename.
* `logging_setup.py`: app-start rotating JSON logs, 256 KiB plus two backups. Only timestamp, level, job ID and state are written. No target, command line, exception message or evidence is logged. Unwritable logging storage does not prevent application startup.

The command-line entry points remain synchronous for compatibility. They share assessment, result and redaction code but do not use the GUI scheduler or persist project history.

## Authorization and scope

Changing target, profile or execution environment clears tool-window authorization. Submission captures immutable values. Permission is checked again in the execution layer before DNS or subprocess launch. Public network/tool targets additionally require exact typed confirmation. This is attestation, not proof of ownership.

Network scope is one IP, one hostname or an existing private-network classification limited to 256 addresses; public CIDRs are rejected. Nmap hostnames are resolved once and only the first checked address is passed to Nmap, with `-n`, explicit TCP connect scanning and IPv6 selection where needed. Other resolved addresses are listed as unassessed. sslscan similarly uses one checked IP with original SNI. IPv6 zone identifiers are rejected rather than silently changed.

Built-in HTTP checks send one request to the exact approved URL, never follow redirects and do not store response bodies. WhatWeb is explicitly configured to never follow redirects and uses one thread. Nikto explores paths under the approved website using existing fixed tuning groups; approval must cover the site, not just a single page. Tool descriptions expose the broader request volume and TLS probe behavior.

Native WhatWeb/Nikto use hostname-based scope and may resolve the approved hostname again. This does **not** guarantee IP-level isolation against DNS rebinding, malicious plugins, proxies or compromised external tools. WSL/Docker WhatWeb requires an explicit IP URL because cross-environment resolution can differ. Do not use hostname-based external checks where policy requires a strict IP allowlist; use isolated infrastructure until an enforced egress boundary is implemented. System DNS resolution itself can be delayed by the OS and is not forcibly interruptible.

## Execution environments and resource budget

Native Windows is the default and needs no GPU, WSL or Docker. One active task and bounded queues/output limit ordinary overhead on a 16 GB machine. Native tools are not subject to a hard memory cap and performance on older 16 GB hardware has not been benchmarked. Parser and inventory limits still apply. Slow all-port profiles remain explicitly selectable.

In **Security tools**, select `wsl` and detect installed distributions or type the exact registered name. The optional PATH check reports whether the supported adapters and GNU `timeout` are available without starting an assessment. For Docker select `docker` and enter a trusted local image ID or repository digest. WSL maps Windows local-drive temp paths through `/mnt/<drive>`. UNC/custom automount layouts are unsupported. Stop ends the Windows WSL launcher, but Linux work can continue until its remote timeout; the UI explicitly warns before starting. Treat WSL as experimental.

Docker streams WhatWeb and sslscan reports through stdout. Its runner supplies a writable job mount only for arguments that reference the job directory. It uses a read-only root filesystem, limited temporary storage, 512 MiB memory, one CPU, 64 processes, no capabilities, no privilege escalation and `--pull=never`. Cleanup forcibly removes the uniquely named container even on launcher failure. Docker engine failure can still prevent cleanup. The native Windows installer ships hash-pinned upstream tools. Optional WSL and Docker backends use existing environments. Container/WSL loopback refers to that environment, not necessarily the Windows host. Never substitute another target just to make connectivity work.

## Evidence and history semantics

External output remains in bounded memory and temporary files, which are removed after parsing. Raw output files are never copied into history. Findings and coverage pass through redaction before UI delivery, storage and HTML reporting. The SQLite database is local and unencrypted; access is governed by Windows account/file permissions. Historical raw records predating redaction can still exist on disk. Evidence retention is not secure erasure.

Nonzero external exit codes, timeouts and truncated output cannot be reported as completed. A cancelled job cannot be overwritten by a late successful return. A closed window cancels its work; closing the app cancels all registered jobs. Closing before result delivery may discard the result, as before. Jobs are not durably queued and cannot resume after a crash. Lifecycle events are saved with delivered scan results, not as a crash-proof audit journal.

Offline dependency results remain partial: supplied-feed coverage, freshness and authenticity are not verified. Matching a version range is not proof of exploitability. Advisory IDs do not imply severity, so normalized matches use informational severity with explanatory evidence.

## Adapter acceptance contract

Add a `ToolSpec`, parser fixtures for actual supported versions, authorization/argv tests, positive and negative local fixtures, explicit request coverage, timeout/cancellation behavior and actionable remediation. Preserve raw severity provenance when available; otherwise label estimates. Never add arbitrary command execution, automatic exploitation, brute force, unattended installs or broad scanning to a beginner button. Test backend compatibility separately before enabling it.

## Verification and remaining release gates

Tests include isolated HTTP/TLS servers, SQLite reopen/redaction, real subprocess cancellation and output bounds, queue backpressure, shutdown, pre-authorization DNS denial, address pinning, partial exit handling, source/confidence, backend argument construction/cleanup and Tk-to-worker-to-HTTP-to-history flows. Backend command tests use a recording runner; they are not live WSL/Docker tests. CI runs Windows and Linux on Python 3.10 and 3.14; Linux uses a virtual display and GUI tests must not silently skip in CI.

The offline installer was exercised under Wine and its Kali tools ran against isolated HTTP and TLS fixtures on a Linux Docker engine. Native WSL 2 provisioning, Docker Desktop on Windows, independently audited scope enforcement, native third-party installer compatibility, detached-child cancellation, 16 GB hardware profiling and long-duration soak testing remain unverified. See the PR checks for the actual CI outcome and ROADMAP.md for release gates.

Reference behavior checked against [WhatWeb options](https://github.com/urbanadventurer/WhatWeb/blob/master/whatweb), [sslscan SNI implementation](https://github.com/rbsec/sslscan/blob/master/sslscan.c), [WSL commands](https://learn.microsoft.com/en-us/windows/wsl/basic-commands) and [Docker run documentation](https://docs.docker.com/reference/cli/docker/container/run/). These references do not substitute for runtime compatibility tests.
