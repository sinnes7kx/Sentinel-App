# Sentinel v0.5 development — shared assessment execution

* Preserves Tkinter and existing tool/dependency functionality; no ZIP replacement or destructive database migration.
* Shares a single bounded task manager across windows, with queued/running/terminal events, cancellation and app-wide shutdown.
* Enforces attestation before DNS and captures target/profile/backend choices at submission. Nmap and sslscan use a checked address; WhatWeb redirects are disabled.
* Adds best-effort redaction, source/confidence, dependency project history and rotating metadata-only logs.
* Treats nonzero exits and bounded-output truncation as incomplete coverage.
* Adds optional explicitly configured WSL/Docker backends for selected tools. Runtime compatibility and WSL cancellation remain experimental; see ARCHITECTURE.md.
* Adds scheduler, subprocess, scope, history, backend and real Tk/loopback integration tests; CI requires GUI availability.

## Historical 0.2.0 notes

A complete replacement source release; existing SQLite projects and history remain readable. No database migration is necessary. Back up the database before updating. v0.1 results are deliberately not compared against v0.2 results because check coverage changed.

## New
- Expanded single-response web posture checks: permissions policy, opener policy, report-only CSP, permissive referrer policy, SameSite=None without Secure, wildcard/conflicting CORS, legacy XSS header and duplicate Content-Type. These are configuration observations, not confirmed exploits.
- Negotiated TLS protocol and cipher strength observations; no protocol/cipher enumeration or certificate bypass.
- Optional exact-domain DNS assessment: SPF and DMARC observations, MX and CAA answer counts. No DKIM selector discovery, inherited DMARC/CAA analysis, SPF expansion or DNSSEC validation. Uses the configured resolver, at most four logical lookups; the resolver may perform retries or follow DNS aliases. DNS checks require optional dnspython; absence or error is shown as incomplete, not a clean result. No raw DNS TXT records stored.
- Stop button (cooperative cancellation between operations; cannot interrupt an already blocked socket/DNS call), coverage details, JSON report export, CLI with explicit authorization and output files.
- Retests require matching assessment profile, URL, optional DNS domain and HTTP status, and completed results.
- Added local verified/untrusted TLS fixture, mocked DNS, cancellation, CLI and regression tests.

## Verification
23 automated tests passed in the Linux build environment, including local HTTPS trust checks using a generated temporary certificate. GUI initialized and closed in a virtual display. No public sites queried. Live DNS resolver behavior and native Windows desktop execution remain unverified. No active exploit testing, automated remediation, AI, licensing, payments or enterprise readiness claimed.
