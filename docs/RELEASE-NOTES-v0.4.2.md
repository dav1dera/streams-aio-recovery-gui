# Streams AIO Recovery 0.4.2 — local test build

The test restore of `dr-20261009T194149Z` stopped during native AIO restoration.
The read-only comparison proved that AIOStreams matched the encrypted capsule
and the original deployment. AIOMetadata had the same values for every present
credential, but lacked the original `FANART_API_KEY` variable. Private values
and their fingerprints were not written to the diagnostic report.

Recovery now handles a missing AIOMetadata `FANART_API_KEY` only when adding an
empty value for that one variable reconstructs the **entire exact fingerprint**
in the encrypted capsule. A missing nonempty Fanart key, any changed value,
other missing secrets, different images and different capsule scopes still
refuse restoration. Capture and existing backup manifests are unchanged.
Fanart is an optional artwork setting in the [upstream documentation](https://github.com/cedya77/aiometadata/blob/dev/docs/ENVIRONMENT_VARIABLES.md).

An AIO validation error occurs before the database installation journal exists.
The standalone probe previously required that journal on retry and returned the
generic `HOST_CHECK_REFUSED` when it was absent. Detection and the trusted runner
now admit this preinstallation state only after verifying the original capsule,
checkpoint scope, empty application runtime, and absence of all native database
outputs, SQLite sidecars, markers and orphan staging directories. Existing
partial journals retain their original strict checks. Detection does not write
or repair checkpoints.

Local validation: 123 targeted checks, 122 passed and one Linux-specific test
skipped on Windows. Real SQLite capsule -> binding failure before the journal ->
standalone probe -> trusted policy -> recovery retry was verified. Tests also
cover missing/changed nonempty keys, unrelated missing empty secrets, foreign
databases, SQLite sidecars, orphan staging and malformed journals.

Use **Rileva e continua** with the same backup, commit and private age identity.
No reset is needed for this preserved attempt. This build remains local; the
full live restore, application logins, domain routing and reboot acceptance have
not yet passed.
