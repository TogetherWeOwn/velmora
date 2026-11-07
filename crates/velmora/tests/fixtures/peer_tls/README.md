# Synthetic TLS fixture

`ca.der` is a test-only CA. `server.der` is its leaf certificate for
`nntp.fixture.invalid`. `server-key.der` is a public, test-only PKCS#8 EC key:
it is not a deployment or provider credential and must never be used outside
these tests. The CA private key was discarded.

Generated fresh with OpenSSL 3 using P-256, SHA-256, a CA with critical
`CA:TRUE` and `keyCertSign,cRLSign`, and a leaf with critical `CA:FALSE`,
`digitalSignature`, `serverAuth` and DNS SAN `nntp.fixture.invalid`. Certificate
validity starts 2026-11-04 and lasts 36,500 days. Tests supply a fixed certificate
clock (2027) and explicitly test times before and after the validity interval;
they do not depend on the host clock or trust store.

Fixture roots and loopback/ephemeral-port injection exist only under `cfg(test)`.
The production adapter uses the Mozilla public roots, a public literal peer and
ports 119/563. Native fixture tests do not qualify the Worker runtime, its
entropy/clock path, or physical socket closure.
