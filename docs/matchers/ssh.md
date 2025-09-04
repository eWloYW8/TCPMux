# SSH Matcher

The `ssh` matcher identifies SSH protocol connections by checking for the presence of the SSH protocol banner at the beginning of the data stream.

This matcher requires no parameters.

**Example**:

This rule matches any connection that begins with the SSH banner and routes it to an SSH handler.

```yaml
rules:
  - name: "ssh-rule"
    type: "ssh"
    handler:
      name: "ssh-passthrough"
      type: "passthrough"
      parameter:
        backend: "localhost:22"
```