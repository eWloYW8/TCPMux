# Regex Matcher

The `regex` matcher uses a regular expression to match against the initial bytes of a connection.

### Configuration

- **`pattern`** (`string`, **required**): The regular expression pattern to match.

**Example**:

This rule matches `SSH` traffic by looking for `SSH` at the beginning of the connection data.

```yaml
rules:
  - name: "ssh-rule"
    type: "regex"
    parameter:
      pattern: "^SSH"
    handler:
      # ...
```