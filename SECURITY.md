# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | ✅ Active support  |
| 1.1.x   | ✅ Security fixes  |
| 1.0.x   | ❌ No longer supported |

---

## Our Security Model

SniffPal is a **100% client-side, local-first** application.

- ❌ No servers — we have none
- ❌ No database — nothing is stored remotely
- ❌ No accounts — no personal data collected
- ❌ No telemetry — we don't track usage
- ✅ All processing happens in your browser
- ✅ Your network captures never leave your machine

This means the attack surface is intentionally minimal.

---

## Reporting a Vulnerability

If you discover a security vulnerability in SniffPal,
please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

Email: security@sniffpal.dev *(monitored by maintainer)*

Or use GitHub's private vulnerability reporting:
- Go to the **Security** tab on this repo
- Click **"Report a vulnerability"**
- Fill in the details

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

---

## Response Timeline

| Stage | Timeline |
|---|---|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix or mitigation | Within 30 days |
| Public disclosure | After fix is deployed |

---

## Scope

### In Scope
- XSS vulnerabilities in the UI
- Malicious pcap/JSON file parsing exploits
- Logic errors in security detection algorithms
- Privacy leaks (data leaving the browser unexpectedly)
- Dependency vulnerabilities with real impact

### Out of Scope
- Issues requiring physical access to the machine
- Social engineering attacks
- Vulnerabilities in Wireshark itself
- Browser-level security issues (report to browser vendor)

---

## Security Best Practices for Users

Since SniffPal analyses network captures:

- ✅ Only open pcap/JSON files from trusted sources
- ✅ Keep your browser updated
- ✅ Do not share your capture files — they contain network data
- ✅ Delete capture files after analysis
- ❌ Never commit pcap files to public repositories

---

## Acknowledgements

We appreciate responsible disclosure.
Verified reporters will be credited here (with permission).

---

*SniffPal — Open Source Network Intelligence*
*https://kannanokannan.github.io/sniffpal*
