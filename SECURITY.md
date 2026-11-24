# Security Policy

## Supported versions
Only the latest release receives fixes.

## Reporting a vulnerability
Please **do not** open a public issue for security problems. Use GitHub's private reporting:
**Security → Report a vulnerability** on this repository. Include steps to reproduce and the
impact. You can expect an acknowledgement within a week.

## Scope
scam-lens runs locally and makes no network requests. Relevant reports include, for example,
a crafted message or rule-pack file that causes excessive CPU use (regular-expression
backtracking), crashes, or unexpected file access.

## Not a security guarantee
scam-lens recognises known patterns only. "No known red flags" never means a message is safe.
