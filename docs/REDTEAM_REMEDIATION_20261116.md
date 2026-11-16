# Red-team remediation: 2026-11-16

The three confirmed findings were unauthenticated loopback proxy identity,
fail-open login admission after counter-store errors, and unbounded persistent
counter cardinality. The production hostile-content corpus confirmed effective
render-time containment, while preserving a deceptive HTTPS link without a scam
warning. Reader wording now states that sender/link identity is unverified and
downloaded files may be malicious. No reputation or phishing detection is claimed.

Production HTTP requires `OSMAP_PROXY_TOKEN_FILE`: an absolute regular file,
owned by the Web runtime UID, mode 0600, one link, containing 64 random hexadecimal
characters with optional final newline. Generate 32 random bytes locally on the
server. Keep this proof outside Git. The root-only mode-0600 nginx include
`/etc/nginx/osmap-proxy-auth.conf` must set `X-OSMAP-Proxy-Token` to that same value.
Every proxy location must overwrite this header; never pass a browser's value.
The Web runtime loads it before confinement and removes the header before routing.
Rotate by coordinating the file, nginx reload and Web restart. A missing or unsafe
file stops production startup; a missing/wrong request proof receives 403 before
forwarded identity or authentication is processed. Keep TCP loopback binding.

This authenticated hop closes the demonstrated service-account attack. A future
Unix socket with peer credential checks can reduce secret custody further.
Compromise of nginx or the Web UID remains privileged within this boundary.

`osmap --version` reports the build's source commit. For source archives supply
`OSMAP_BUILD_REVISION` to the build. Release deployment must retain the source
commit and binary SHA-256 together; version text alone is not a signature.

The original sealed assessment remains historical evidence. Deployment results
and regression counts are recorded in the decision log after execution.
