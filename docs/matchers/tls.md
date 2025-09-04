# TLS Matcher

The `tls` matcher matches against the Server Name Indication (SNI) and Application-Layer Protocol Negotiation (ALPN) values presented during the TLS handshake.

!!! note
    This matcher requires `tls.enabled: true` in your main configuration.

### Configuration

- **`sni`** (`string`, **optional**): The SNI to match. If omitted, any SNI will match.
- **`alpn`** (`[]string`, **optional**): A list of ALPN protocols to match. If omitted, any ALPN will match.

**Example**:

```yaml
rules:
  - name: "example-com-tls"
    type: "tls"
    tls_required: true
    parameter:
      sni: "example.com"
      alpn:
        - "h2"
        - "http/1.1"
    handler:
      # ...
```