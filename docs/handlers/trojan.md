# Trojan Handler

The `trojan` handler implements a Trojan proxy server, enabling clients to forward their **TCP** and **UDP** traffic through the handler. It requires clients to authenticate with a pre-shared password and handles both connection and association requests.

The [Trojan Matcher](../matchers/trojan.md) and [Trojan Handler](../handlers/trojan.md) are designed to be used together.

### Configuration

  * **`passwords`** (`[]string`, **optional**): A list of valid passwords for the Trojan connection. The handler will validate the client's provided password against this list. If this list is empty, authentication is not performed at the handler level, but it is typically enforced by the matcher.

### Example

This configuration sets up a Trojan handler that requires clients to authenticate using one of the two specified passwords before it processes their requests.

```yaml
handler:
  name: "secure-trojan"
  type: "trojan"
  parameter:
    passwords:
      - "password123"
      - "another-strong-password"
```