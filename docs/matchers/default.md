# Default Matcher

The `default` matcher is a simple catch-all matcher that always returns `true`. It is useful for creating a default rule that handles any traffic not matched by preceding rules.

### Configuration

The `default` matcher has no parameters.

**Example**:

```yaml
rules:
  - name: "default-catch-all"
    type: "default"
    handler:
      # ...
```