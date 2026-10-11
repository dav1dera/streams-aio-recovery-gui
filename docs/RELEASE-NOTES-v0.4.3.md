Streams AIO Recovery 0.4.3
=========================

Resume the prepared recovery using the same complete backup, commit and age
identity. A reset is not needed for these fixes.

* NPM's native Cloudflare DNS-01 helper now uses the environment initialized by
  NPM's backend, including its detected Certbot version and NPMHOME.
* Final HTTPS readiness distinguishes the recovered services from devices
  outside the two restored VMs. The original backup bindings and the applied
  routing journal must agree before any route can be classified as external.
  Mixed routes with recovered locations remain mandatory.
* An external application returning 5xx or timing out is displayed and saved
  as an external dependency to check. Its route is preserved. All certificate
  checks remain mandatory, including on external routes. A failed recovered
  application still stops recovery.
* The completion banner retains external dependency warnings and does not
  claim login, AIO profile or end-to-end functional acceptance.

Observed cause in the current test: NPM host 26 forwards the Stremio domain to
192.168.178.20:11470, outside the restored .29/.30 scope. Its TLS certificate is
valid; the external destination is unreachable and NPM returns 502. The other
14 associated HTTPS hosts pass the native HTTP-status criterion. All 28 active
stack services are running/healthy, including Comet and CometNet. Three public
controllers remain deferred during the parallel test.

The adapter supports the exact native scripts in stack commit
184ace9a86ee180ab791bf01edd7be3953c48992 and refuses changed scripts. It does not
modify the restored tracked Git tree, certificates' reuse policy or routing.

Live acceptance of this build remains pending until a GUI resume completes.
The external Stremio device and the final application login/profile checks
must still be tested before claiming full production equivalence.
