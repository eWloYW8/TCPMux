# Timeout Matcher

The `timeout` matcher is unique as it doesn't match based on data. It is triggered if no other rule has matched a connection within a specified timeout period.

!!! note
    You can only have one `timeout` rule.

### Configuration

- **`timeout`** (`int`, **required**): The timeout duration in seconds.

**Example**:

```yaml
rules:
  - name: "idle-timeout-rule"
    type: "timeout"
    parameter:
      timeout: 30
    handler:
      # ...
```