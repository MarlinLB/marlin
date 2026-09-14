# Security Policy

## Supported Versions

Marlin has not yet made a release (`README.md`: "design settled, pre-implementation").
Until a first release exists, only `main` is supported.

| Version | Supported |
|---|-----------|
| main    | ✅        |

This table gains real release lines once versioning starts — see `PHASES.md`.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately, not via a public issue.

Use GitHub's private vulnerability reporting on this repository: **Security** tab →
**Report a vulnerability**. Reports are routed to the repository's `security` team.

Include the affected component (datapath / marlind / control plane / deploy config), a commit or
version, reproduction steps, and impact.

## Scope

In scope: `data-plane/` (XDP datapath, including `marlind/`, the data-plane loader),
`control-plane/` (C#), `deploy/` (unit and config files).

Out of scope: `bpftool` and other third-party dependencies not modified by Marlin.

## Disclosure

**Acknowledgement:** within 5 working days of receipt.

**Credit:** Reporters are credited by name or handle by default. Anonymity is opt-out —
credit is withheld only if the reporter asks.

**CVE / advisory process (draft):** No CVEs or GitHub Security Advisories will be issued
before Marlin's first release, consistent with the Supported Versions table above. Once a
first release exists, advisories for vulnerabilities affecting a released version will be
published as GitHub Security Advisories on this repository, and a CVE requested where
applicable. Subject to revision once `PHASES.md` versioning actually starts.
