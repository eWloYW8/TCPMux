# Matchers

Matchers are the core of TCPMux's routing logic. They analyze incoming connection data to determine which rule to apply.

Each matcher is configured with a `parameter` field in the rule definition.

The following matchers are available:

- [Default](default.md)
- [Regex](regex.md)
- [Substring](substring.md)
- [TLS](tls.md)
- [Timeout](timeout.md)
