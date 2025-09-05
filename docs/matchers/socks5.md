# SOCKS5 Matcher

The `socks5` matcher identifies a connection as a SOCKS5 proxy request based on its initial handshake. It can be configured to check for the presence of specific authentication methods offered by the client.

The [SOCKS5 Matcher](../matchers/socks5.md) and [SOCKS5 Handler](../handlers/socks5.md) are designed to be used together.

### Configuration

  - **`allowed_methods`** (`[]string`, **optional**): A list of SOCKS5 authentication methods that the matcher will accept. If this list is empty, the matcher will accept any valid SOCKS5 handshake regardless of the authentication methods offered. Accepted values are `no_auth` and `username_password`.

### Example

#### 1. Matching any valid SOCKS5 request

This rule matches any legal SOCKS5 handshake, forwarding the connection to a handler that may or may not enforce authentication.

```yaml
rules:
  - name: "any-socks5"
    type: "socks5"
    handler:
      # ...
```

#### 2. Requiring username/password authentication

This rule only matches SOCKS5 handshakes where the client offers `username_password` as an authentication method. This is useful for routing connections to a handler that enforces authentication.

```yaml
rules:
  - name: "auth-socks5"
    type: "socks5"
    parameter:
      allowed_methods:
        - "username_password"
    handler:
      # ...
```