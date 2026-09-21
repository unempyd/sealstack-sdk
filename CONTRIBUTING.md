# Contributing

Bug reports: open an issue on this repository with the SDK version, the
command or code that ran, and what you expected. A minimal evidence bundle
that reproduces a verifier result is the most useful attachment.

Pull requests are welcome. Keep a change to one concern, add or adjust a test
under `sdk/tests` or `reference-server/tests`, and make sure `pytest`, `ruff
check .` and `mypy --strict --explicit-package-bases sdk/sealstack
reference-server` pass. This repository is an export of the SDK from the
SealStack source repository, so a merged change is carried back there and
re-exported rather than edited here in place.

Security issues: do not open a public issue. Use
[GitHub private vulnerability reporting](https://github.com/unempyd/sealstack-sdk/security/advisories/new)
or write to `SealStack@icloud.com` (copy the address; it is not a link), as
described in SECURITY.md.
