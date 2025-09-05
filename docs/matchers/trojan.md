# Trojan Matcher

The `trojan` matcher identifies a connection as a Trojan proxy request based on its initial handshake. It validates the client's provided password. The matcher requires the connection to be a **TLS connection**.

The [Trojan Matcher](../matchers/trojan.md) and [Trojan Handler](../handlers/trojan.md) are designed to be used together.

### Configuration

  * **`passwords`** (`[]string`, **optional**): A list of valid passwords for the Trojan connection. The matcher will check if the client's password (hashed using SHA224) matches any of the passwords in this list. If the list is empty, the matcher will only check for the correct Trojan protocol format without enforcing a specific password.

### Example

#### 1. Matching any valid Trojan request without a specific password

This rule matches any legal Trojan handshake, as long as it follows the correct protocol format, and routes the connection to a handler. This can be useful for setups that do not require password validation at the matcher level.

```yaml
rules:
  - name: "any-trojan"
    type: "trojan"
    handler:
      # ...
```

#### 2. Requiring a specific password

This rule only matches Trojan handshakes where the client's provided password (hashed using SHA224) is `p@ssw0rd`. This is useful for routing connections that require specific authentication.

```yaml
rules:
  - name: "auth-trojan"
    type: "trojan"
    parameter:
      passwords:
        - "p@ssw0rd"
    handler:
      # ...
```