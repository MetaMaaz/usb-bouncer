# Security Policy

## Supported Versions
The latest tagged release is supported. Older tags receive no fixes.

## Reporting a Vulnerability
Please open a private security advisory via GitHub
(Security tab -> Report a vulnerability) rather than a public issue.
Target first response: 5 business days.

## Scope
This policy covers usb-bouncer's own code: parsing untrusted device
descriptors, the keystroke event tap, and the report writer. It does not
cover third-party dependencies (see Dependabot alerts).

Note that usb-bouncer parses attacker-controlled input by design — a
malicious USB device fully controls the descriptor strings this tool reads.
Parser crashes, injection into the JSONL log, and path traversal via device
names are all in scope and are the bugs most worth reporting.
