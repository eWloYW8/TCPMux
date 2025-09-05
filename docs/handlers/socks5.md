# SOCKS5 Handler

The `socks5` handler acts as a SOCKS5 proxy server, enabling a client to establish a **TCP** connection to a destination through the handler. It supports standard SOCKS5 commands and optional username/password authentication for enhanced security.

The [SOCKS5 Matcher](../matchers/socks5.md) and [SOCKS5 Handler](../handlers/socks5.md) are designed to be used together.

### Configuration

  * **`username`** (`string`, **optional**): If provided, the handler will enforce username/password authentication. The client must supply this username to proceed.
  * **`password`** (`string`, **optional**): The password to be used in conjunction with the username for authentication. If both `username` and `password` are empty, authentication is not required.

### Example

This configuration sets up a SOCKS5 handler that requires clients to authenticate with the specified username and password.

```yaml
handler:
  name: "secure-socks5"
  type: "socks5"
  parameter:
    username: "myuser"
    password: "securepassword"
```