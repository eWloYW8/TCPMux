# Configuration

TCPMux uses a single YAML configuration file to define its behavior. The file specifies network listeners, logging settings, and a set of rules for routing traffic.

## File Structure

A typical `config.yaml` file looks like this:

```yaml
listen:
  - "0.0.0.0:443"

logging:
  level: "info"
  stderr: true

tls:
  enabled: true
  config:
    - sni: "myservice.com"
      cert: "path/to/myservice.com.crt"
      key: "path/to/myservice.com.key"

rules:
  - name: "my-tls-rule"
    type: "tls"
    tls_required: true
    parameter:
      sni: "myservice.com"
    handler:
      name: "my-handler"
      type: "passthrough"
      parameter:
        backend: "127.0.0.1:8443"
        tls:
          enabled: true
          insecure_skip_verify: true

controller:
  enabled: true
  listen: "127.0.0.1:12067"
```

## Using YAML Anchors

For complex configurations with many rules, it's highly recommended to use **YAML anchors (`&`) and aliases (`*`)** to define handlers once and reuse them across multiple rules. This prevents repetition and makes your configuration file much cleaner and easier to manage.

**Anchor (`&`)**: Defines a reusable block.
**Alias (`*`)**: Refers to a defined anchor.

### Example with Anchors

```yaml
tls:
  enabled: true
  config:
    - sni: "*.example.com"
      cert: /path/to/cert.pem
      key: /path/to/key.pem
    - sni: "*"
      cert: /path/to/default_cert.pem
      key: /path/to/default_key.pem

handler:
  - &ssh_handler
    name: "SSH Handler"
    type: "passthrough"
    parameter:
      backend: "127.0.0.1:22"
      tls: 
        enabled: false
  - &http_handler
    name: "HTTP Handler"
    type: "passthrough"
    parameter:
      backend: "127.0.0.1:80"
      tls: 
        enabled: false

rules:
  - name: "SSH Rule"
    type: "substring"
    parameter:
      offset: 0
      value: "SSH-"
    handler: *ssh_handler

  - name: "HTTP Rule"
    type: "regex"
    parameter:
      pattern: "^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT)\\s+\\/?.*?\\s+HTTP\\/[0-9.]+"
    handler: *http_handler

  - name: "default Rule"
    type: "default"
    handler: *ssh_handler
  
  - name: "timeout Rule"
    type: "timeout"
    parameter:
      timeout: 5
    handler: *ssh_handler

logging:
  level: "debug"
  stderr: true
  file: "TCPMux.log"
  format: "console"

listen:
  - "[::]:10443"
  - "[::]:24067"
```