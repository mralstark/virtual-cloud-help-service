# Security policy

This repository is pre-production. Do not deploy it for users until the milestone
exit criteria and an external security review are complete.

The in-repository review and automated checks reduce known implementation risk but
are not an independent audit. The control plane is supported only on Linux; signing
key operations fail closed elsewhere until equivalent file permissions and process
locking are implemented and reviewed.

Please report vulnerabilities privately through GitHub's security advisory feature.
Do not include real device keys, server credentials, client IP addresses, browsing
destinations, DNS logs, or packet captures in a public issue.

Only the latest commit on `main` is considered for security fixes during bootstrap.
No released version is currently supported.
