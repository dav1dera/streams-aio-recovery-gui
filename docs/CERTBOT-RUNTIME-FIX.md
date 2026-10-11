NPM 2.16.0 DNS-01 recovery
========================

The native recovery helper previously invoked Node directly through Docker
exec. That process did not inherit CERTBOT_VERSION exported when NPM starts
its backend. Cloudflare's native plugin installer needs this version when
building its Certbot/acme package requirements.

The authenticated test on .29 confirmed Certbot 5.8.0 was installed, while
the direct helper had no exported version. Sourcing NPM's own common.sh and
setting HOME to NPMHOME yielded the matching version and completed native
issuance, associations, nginx configuration and TLS verification.

The desktop source now invokes npm_runtime.py for both native reissue and
verification. This adapter checks the exact SHA256 of the three public
scripts from the backup and changes only the verified Docker child command.
Private inputs still travel through stdin. Native validation, replacement
ownership, locking, journal updates and certificate reuse remain in place;
the restored tracked Git tree is not edited.

The current supported native scripts are from stack commit
184ace9a86ee180ab791bf01edd7be3953c48992. An unknown or changed script is
refused before loading it.

Validation: five adapter tests, four SSH resource-transfer tests and eleven
operational-domain tests pass. The environment correction also passed live
through the one-shot repair. The updated desktop source is not yet packaged
or accepted as a complete fresh recovery. The user's latest GUI run passed
issuance and replacement-domain identity checks, then stopped during the
final HTTPS response verification. Diagnose that distinct failure before
another certificate request or reset.
