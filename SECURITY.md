# Security Policy

## Supported versions

Only the latest release on the `main` branch receives fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems in this tool (for example, a crafted input that causes code execution, a bypass of a detection, or a false negative on a known attack pattern).

Instead, report privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting).

Include:
- what you found and its impact
- a minimal input or steps to reproduce
- the version or commit you tested

You'll get an acknowledgement within 72 hours. Fixed issues are credited in the changelog unless you prefer to stay anonymous.

## Scope

These are defensive, read-only tools. They never execute the content they scan and never send data over the network. A finding that breaks either of those guarantees is treated as critical.
