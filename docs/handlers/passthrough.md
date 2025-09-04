# Passthrough Handler

The `passthrough` handler simply forwards all traffic from the client to a specified backend service and vice versa. It is the most common handler for proxying traffic.

### Configuration

- **`backend`** (`string`, **required**): The address of the backend service (e.g., `127.0.0.1:8000`).
- **`tls`** (`BackendTLSConfig`, **optional**): Configuration for TLS to the backend.

### `BackendTLSConfig`

- **`enabled`** (`bool`, **optional**): If `true`, TCPMux will initiate a TLS connection to the backend. Defaults to `false`.
- **`insecure_skip_verify`** (`bool`, **optional**): If `true`, the TLS connection to the backend will not verify the backend's certificate.
- **`sni`** (`string`, **optional**): The SNI to use for the TLS handshake with the backend.
- **`alpn`** (`[]string`, **optional**): A list of ALPN protocols to advertise to the backend.

**Example**:

```yaml
handler:
  name: "my-backend"
  type: "passthrough"
  parameter:
    backend: "127.0.0.1:8443"
    tls:
      enabled: true
      insecure_skip_verify: true
      sni: "internal.backend"
      alpn:
        - "h2"
```