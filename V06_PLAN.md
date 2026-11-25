# Sentinel v0.6 — guided assessment and unified engine plan

Product goal: beginner-friendly on the surface, professional underneath. Windows users should not need to learn Kali commands to perform real, authorized security assessments. Use the existing Tkinter, SQLite, scope, orchestration and evidence layers.

## First increment (this branch)

- New assessment opens a guided desktop entry point for the existing quick website, security tools and dependency workflows.
- Local inventory distinguishes detected executable/client presence from verified readiness. No binary launch, installation, network request, or image pull occurs during inventory.
- Existing authorization, target handling, scan profiles, reports and history remain unchanged.
- Adds unit tests for optional tools absent/present and honest readiness labels.

## Next increments and release gates

1. Add bounded and cancellable runtime health checks for Docker/WSL and pinned tool versions. Separate approval for provisioning. Never quietly downgrade or widen scope.
2. Address Windows process-tree termination and enforced network egress before broadening active coverage. Test redirect, DNS rebinding, cancellation and incomplete coverage with isolated fixtures.
3. Add a reviewable assessment plan: plain-language objective, target, checks, backend, coverage gaps and authorization. Only enable execution for validated compatible combinations. Retain evidence provenance, severity separate from confidence, and retesting.
4. Polish desktop navigation, setup and installer. Benchmark older Windows systems with 16 GB RAM; keep a native-only path.
5. After these gates, integrate ZAP in an isolated practice environment, then local dependency, code and container security engines. Add further tools only with versioned tests, license review and useful remediation.

Learning Lab: intentionally vulnerable local fixtures, isolated from unrelated systems. No simulated findings in real assessments. No unattended exploitation or arbitrary tool flags in the beginner flow. Free remains genuinely useful; defer Pro/Business licensing and payment until stable.

Verification: new tests supplied, but this connector-only change has not been run on Windows or in a live Docker/WSL environment. No claim of complete v0.6 or new vulnerability coverage.

## Increment 2 — Engine health checks

The guided window now offers explicit Check engines and Cancel check actions using the shared bounded worker. Docker diagnostics use the standard local named pipe on Windows or Unix socket on Linux, check for a Linux daemon, inspect only the saved local image ID, and run the two bundled tool version commands with no container network, no image pulls, resource limits and best-effort cleanup. WSL diagnostics list distributions and query versions only in the saved distribution with fixed commands and remote deadlines. A WSL distribution can start as a result; WSL is not a network-isolation boundary.

Runtime diagnostics distinguish client detection, daemon response, image presence and reported tool versions from verified assessment compatibility. No raw subprocess diagnostics are shown. Custom Docker sockets and unprepared environments are not supported by these health checks. The checks are informational; they do not select a scan backend or authorize any assessment. Existing Windows process-tree and network egress limitations remain. Added mocked regression tests; native Windows, Docker Desktop and WSL runtime tests remain release gates.

## Increment 3 — Guided assessment planning

New assessment → Website: guided assessment previews Quick or Standard website coverage. Planning is offline: the existing URL parser validates input without resolving DNS or contacting a target. Quick recommends the built-in single-URL configuration checks. Standard additionally previews TLS protocol/cipher review (HTTPS only) and passive technology identification. Native executable detection takes precedence; Docker and WSL are candidates only when prepared tool version probes succeeded. No alternate target is substituted, and loopback/link-local targets are not recommended for alternate runtimes. Hostname-based external technology checks are deferred until strict IP egress controls exist.

The plan is advisory. A version result is not proof of compatible scans; no external tool is started or selected for execution. Continue to quick check transfers the exact parsed URL into the main form, clears optional DNS and resets authorization. The user must explicitly approve and start the existing assessment. Additional checks remain manual in Security tools. No new vulnerability detection, active scan or network authorization behavior is added. Eight unit test methods cover candidate ordering, missing tools, scope-related limitations, invalid inputs and offline planning. Actual CI and Windows GUI results must be checked before merging.

## Increment 4 — Native process ownership (Phase 1D, first slice)

The shared subprocess runner now attempts to assign each Windows launcher to a kill-on-close Job Object immediately after creation; if assignment fails, the direct process is killed and the check fails. On POSIX it starts a new session and signals the owned process group. Cleanup is attempted on timeout, cancellation, normal completion and exceptions. Inherited pipes that do not close within bounded reader joins mark output incomplete rather than blocking the runner on buffered stream close. Three real local subprocess tests exercise a deliberately spawned child on cancel, timeout and normal parent exit.

This is not a complete process sandbox: Windows has a launch-to-assignment race, nested Job Object policy may reject assignment, POSIX descendants can escape their process group, and escaped descendants may retain a pipe or keep running. Existing Docker and WSL guest cancellation limitations remain; killing a Windows launcher does not prove the Linux guest stopped. Strict network egress, DNS rebinding tests, verified Docker/WSL cleanup and Windows runtime verification remain outstanding. No new network scan or vulnerability coverage is added. CI results are not yet verified.

## Increment 5 — Built-in HTTP scope protection (Phase 1E, first slice)

The built-in website engine now captures a single DNS snapshot after permission attestation (IP literals bypass DNS). The socket factory connects only to numeric endpoints in that snapshot, verifies the peer address, and keeps the original HTTP Host and TLS hostname verification. TCP fallback is limited to the captured addresses and a shared connection budget. Mixed global/non-global answers, unspecified, multicast, link-local and scoped IPv6 endpoints are rejected. Existing no-redirect behavior remains. Completed results record the selected address and other resolved addresses; retests with different addresses or one missing address are not comparable. Eight new local regression tests cover DNS rebinding simulation, Host preservation, redirect denial, unauthorized resolution, address rejection, cancellation and retests.

This guards against a second resolution changing the connection address, not malicious initial DNS answers or a change in ownership of the address. It does not independently establish permission, enforce operating-system network egress, guarantee a hard DNS deadline, isolate third-party tools, or cover optional DNS/email checks. Hostname-based external tooling, Docker/WSL egress, cancellation limitations and independently reviewed scope enforcement remain release gates. No new vulnerability scanners or broader scan coverage are enabled. CI and native Windows runtime results have not been verified.

## Increment 6 — Executable native Standard assessment (Phase 1F, first slice)

Quick remains the original website configuration assessment. Standard now runs the same authorized check followed by verification of TLS 1.2 and TLS 1.3 on the exact numeric endpoint and port that completed the first connection. The initially negotiated version counts as verified; the remaining version is probed with a certificate-validating context restricted to that version. No further DNS lookup, HTTP request or redirect occurs during the additional TLS handshake. Failed negotiation is inconclusive, not evidence that a version is disabled. HTTP URLs skip TLS follow-ups; failed/incomplete base assessments do not trigger them. Cancellation is cooperative between bounded operations. Standard uses a separate profile identifier and the existing scheduler, history and exports.

The guided planner transfers the selected profile and resets authorization. Native and external tool candidates remain distinct: automatic external execution is not enabled. Standard does not enumerate ciphers or legacy TLS protocols, and does not perform active application vulnerability testing. Eight new test methods include a real loopback TLS 1.2-only fixture. CI and native Windows verification remain pending; strict external egress and verified guest cancellation are still release gates.

## Increment 7 — Real Kali tool integration lab (Phase 1G)

A dedicated Linux CI job builds the same digest-pinned Kali base and packaging Dockerfile used for the Windows toolkit, then builds a fixture-only derivative with Python. The test harness launches synthetic HTTP and TLS 1.2-only servers on loopback inside a network-none container. The actual Sentinel Docker adapter is exercised with an injected test runner that joins only that isolated network namespace; no host ports are published. WhatWeb must produce real technology evidence and must not follow a redirect to a separate trap listener. sslscan must identify the synthetic self-signed certificate and TLS 1.3 absence without reporting unsupported legacy-protocol findings. Package versions are printed. The build requires network access to obtain the base and packages; the running lab has no external network interface. Rolling package versions are recorded, not fully locked.

Parser regressions reject missing WhatWeb plugin records and missing sslscan protocol evidence, report capped WhatWeb findings and treat incomplete modern TLS observations as incomplete rather than disabled. Five additional unit tests cover these cases.

This is a CI-only lab, not an end-user Learning Lab. The injected isolation is not enabled for production external-tool scans. Live Docker Desktop/WSL tests, automatic multi-tool execution, production egress enforcement, and ZAP remain outstanding. The lab must pass before claiming real integration verification. Existing Windows installer and scan behavior are otherwise unchanged.

## Increment 8 — Findings and evidence presentation (Phase 1H, first slice)

Shared read-only presentation prioritizes findings by severity while retaining each finding's original confidence, source, ID, evidence and remediation. Only records identical across every saved field within a single assessment are grouped, with explicit repeat counts; different tools, locations, confidence values, evidence and remediation remain separate. Desktop main results, Security tools results and HTML export use the same presentation. Raw saved findings, JSON export, scan execution, comparison behavior and existing database schema remain unchanged. Retesting guidance makes clear that absence of an observation is not proof of resolution.

This is conservative presentation deduplication, not cross-tool vulnerability correlation. The existing suite's legacy header suppression remains unchanged and may discard evidence before presentation. Scope-aware cross-tool correlation and remediation status tracking require a later evidence model. Six regression tests cover grouping, non-mutation, priority and confidence separation, legacy records, empty results and export escaping/redaction. Previous Kali lab PR #7 passed CI and was merged; new Phase 1H checks remain to be verified.
