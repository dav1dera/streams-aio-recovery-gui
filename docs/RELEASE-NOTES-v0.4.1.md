# Streams AIO Recovery 0.4.1 — local test build

The Windows 0.4.0 executable bundled `remote/bootstrap.sh` with CRLF line endings
(73 CRLF lines), although the reviewed local source used LF. This can prevent Bash
from reaching the first progress event and leave the GUI reporting only
`REMOTE_OPERATION_FAILED`.

Shell scripts now have an explicit LF checkout policy. Both the executable
self-test and the recovery path check the bytes of bundled shell scripts. An
invalid package is refused with `REMOTE_SCRIPT_FORMAT_INVALID` before recovery
commands or staging changes on either VM. The advanced page also provides
**Rimuovi** for previously selected AIO JSON exports.

Local validation: 31 targeted tests passed; all 17 remote resources in the new
executable matched the reviewed local source exactly; its bootstrap contained
zero CRLF lines; the built executable's `--self-test` passed. The local sandbox
did not allow the optional Git Bash reproduction, so no Bash execution result
is claimed from that probe.

The full two-VM restore, AIO logins, domain routing, HTTPS/CometNet, interruption
resume and reboot acceptance still require live validation. This local build
has not been published to GitHub. Existing VM checkpoints and archived attempts
are preserved; use **Rileva e continua** with the same backup, commit and private
age identity to continue the test.
