# Public laboratory-only TLS fixture

The CA certificate and server private key in this directory are public test
material, not secrets. Never install or trust this CA system-wide; never use
these certificates or this key outside the isolated local laboratory. The CA
private key was temporary and is not retained here. The server certificate
has the sole DNS SAN `standard-lab.invalid` and expires 28 October 2036.
The lab uses its CA only in an explicitly constructed client context. DNS and
public peer identity are simulated and no public TLS deployment is assessed.
