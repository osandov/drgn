# Security Policy

## Threat Model

See the
[documentation](https://drgn.readthedocs.io/en/latest/api_reference.html#threat-model)
for drgn's threat model and what is considered a security issue.

## Reporting a Vulnerability

Please report security issues using [GitHub's private vulnerability
reporting](https://github.com/osandov/drgn/security/advisories/new). Include a
reproducer if possible.

Bugs that are not security issues according to the threat model should be
reported as normal [issues](https://github.com/osandov/drgn/issues).

Bugs in drgn's dependencies (e.g., elfutils, libkdumpfile) should be reported
to those projects.

## Supported Versions

Security fixes are only applied to the `main` branch and included in the next
release.
