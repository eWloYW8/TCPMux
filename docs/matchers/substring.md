# Substring Matcher

The `substring` matcher checks if a specific byte sequence exists within the initial data of a connection, starting from a given offset.

### Configuration

- **`offset`** (`int`, **required**): The offset in bytes from the start of the data to begin the search.
- **`value`** (`string`, **required**): The substring to search for.

**Example**:

This rule matches HTTP traffic by checking for "GET" near the beginning of the stream.

```yaml
rules:
  - name: "http-rule"
    type: "substring"
    parameter:
      offset: 0
      value: "GET"
    handler:
      # ...
```