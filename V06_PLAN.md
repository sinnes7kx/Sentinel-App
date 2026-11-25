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
