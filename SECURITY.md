# Security and public distribution

This repository contains **recovery software**, not a backup repository. Never commit or publish live recovery archives, Infisical exports, database dumps, `age` identities, SSH private keys, GitHub tokens, passwords, or generated state. The companion DR backup repository and its encrypted releases must remain access-controlled.

## Public-release checks

- Run the `Secret scanning` workflow (Gitleaks, full checkout history) and resolve every finding. No allowlist is configured: inspect any test fixture reported before changing it.
- Independently audit all reachable refs before exposing the repository: `gitleaks git --log-opts="--all" --redact`. A clean working tree alone is insufficient; deleted secrets can remain in earlier commits, branches, and tags.
- Review **every screenshot** in `docs/screenshots/` for credentials, identity information, hostnames, tokens, names, email addresses, and live infrastructure details. Image contents are not reliably covered by text secret scanners.
- Review **all release assets**, including historic source ZIPs and Windows executables. They can contain bundled resources from older revisions. Deleting a file in `main` does not clean prior releases or reachable Git objects.
- Verify that the application works with user-supplied SSH destinations and a user's own backup repositories. The `192.168.178.29` / `192.168.178.30` values in the destructive **test-reset** flow are deliberately fixed to a historical isolated test; do not turn these into unrestricted targets when generalizing examples.
- If a real credential is discovered, revoke/rotate it **first**, then assess Git history rewriting and release replacement. Do not assume `.gitignore` retroactively removes tracked files.

## Reporting vulnerabilities

Do not post potential credentials, plaintext recovery files, or exploit details in public issues or pull requests. Contact the maintainer privately through GitHub before providing sensitive material.

## Review status

This file and the secret-scanning workflow support review; they do **not** certify that existing history, images or release binaries are secret-free.
