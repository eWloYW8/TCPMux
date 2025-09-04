# TLS

The `tls` section allows you to configure TLS for incoming connections.

### Fields

- **`enabled`** (`bool`, **required**): If `true`, TCPMux will attempt to perform a TLS handshake on connections that appear to be TLS.
- **`config`** (`[]SNIConfig`, **required**): A list of TLS configurations for different Server Name Indication (SNI) values.

### `SNIConfig`

- **`sni`** (`string`, **required**): The Server Name Indication hostname. Use `*` to specify a default certificate for any SNI that doesn't have a specific match.
- **`cert`** (`string`, **required**): Path to the certificate file.
- **`key`** (`string`, **required**): Path to the private key file.

**Example**:

```yaml
tls:
  enabled: true
  config:
    - sni: "myservice.com"
      cert: "/etc/ssl/myservice.com.crt"
      key: "/etc/ssl/myservice.com.key"
    - sni: "anotherservice.net"
      cert: "/etc/ssl/anotherservice.net.crt"
      key: "/etc/ssl/anotherservice.net.key"
    - sni: "*"
      cert: "/etc/ssl/default.crt"
      key: "/etc/ssl/default.key"
```