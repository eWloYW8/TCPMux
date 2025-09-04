# Logic Matchers: `and` and `or`

These matchers combine multiple rules to create complex matching logic. They are useful for creating nuanced routing policies based on multiple conditions, such as matching a specific IP from a certain host.


## `and` Matcher

The `and` matcher requires **all** of its sub-matchers to return `true` for a successful match. If any single sub-matcher fails, the entire rule fails.

### Configuration

  - **`matchers`** (`object[]`, **required**): A list of objects, each containing a `type` and `parameter` field that defines a sub-matcher.

### Example

This rule matches a connection only if it originates from the `192.168.1.0/24` subnet **and** contains the substring "Hello" at the beginning of the data stream.

```yaml
rules:
  - name: "internal-and-specific-data"
    type: "and"
    parameter:
      matchers:
        - type: "ip"
          parameter:
            CIDRs:
              - "192.168.1.0/24"
            mode: "allow"
        - type: "substring"
          parameter:
            offset: 0
            value: "Hello"
    handler:
      # ...
```


## `or` Matcher

The `or` matcher succeeds if **any** of its sub-matchers return `true`. It will short-circuit, meaning it stops checking as soon as it finds a successful match.

### Configuration

  - **`matchers`** (`object[]`, **required**): A list of objects, each containing a `type` and `parameter` field that defines a sub-matcher.

### Example

This rule matches a connection if the client's SNI is `example.com` **or** if the HTTP host header is `api.example.com`.

```yaml
rules:
  - name: "tls-or-http-host"
    type: "or"
    parameter:
      matchers:
        - type: "tls"
          parameter:
            sni: "example.com"
        - type: "http"
          parameter:
            hosts:
              - "api.example.com"
    handler:
      # ...
```