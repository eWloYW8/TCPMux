# Port Matcher

The `port` matcher filters incoming connections based on the destination port they were received on. This is particularly useful when TCPMux is listening on multiple ports and you want to apply different routing rules for each port.

### Configuration

  - **`ports`** (`string[]`, **required**): A list of port numbers (as strings) to match against the destination port of the incoming connection.

### Examples

This example demonstrates a single rule matching connections on either port **80** or port **443**. This can be used to consolidate HTTP and HTTPS traffic from a single listener to a common backend handler.

```yaml
rules:
  - name: "web-traffic"
    type: "port"
    parameter:
      ports:
        - "80"
        - "443"
    handler:
      name: "web-handler"
      type: "passthrough"
      parameter:
        backend: "localhost:8080"
```