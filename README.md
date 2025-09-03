# TCPMux

A TCP traffic multiplexer written in Go.

[![Build and Release](https://github.com/eWloYW8/TCPMux/actions/workflows/build.yml/badge.svg)](https://github.com/eWloYW8/TCPMux/actions/workflows/build.yml)

## Installation

```bash
git clone https://github.com/eWloYW8/TCPMux
cd TCPMux
go mod tidy
go build
```

This will create an executable named `TCPMux` (or `TCPMux.exe` on Windows) in your current directory.

or **[Releases](https://github.com/eWloYW8/TCPMux/releases)**

## Usage

```
Usage of TCPMux:
  -config string
        path to config file (default "config.yaml")
```

## Configuration

TCPMux uses a YAML file named `config.yaml` to configure its behavior.

### **Top-Level Configuration**

| Field | Type | Description |
| :--- | :--- | :--- |
| `listen` | `[]string` | A list of addresses for the server to listen on, e.g., `["0.0.0.0:8080", "localhost:8443"]`. |
| `tls` | `TLSConfig` | TLS configuration for handling TLS traffic. |
| `rules` | `[]Rule` | A list of routing rules that define how to match traffic and forward it to backends. |
| `logging` | `LoggingConfig` | Logging configuration to control log level and output. |

### **TLS Configuration (`TLSConfig`)**

| Field | Type | Description |
| :--- | :--- | :--- |
| `enabled` | `bool` | Whether to enable TLS. If `true`, the server will attempt to handle TLS traffic on the listening port. |
| `config` | `[]SNIConfig` | A list of certificate configurations related to **SNI** (Server Name Indication). |

**`SNIConfig`**

| Field | Type | Description |
| :--- | :--- | :--- |
| `sni` | `string` | The **SNI** hostname, e.g., `example.com`. Use `*` for the default certificate. |
| `cert` | `string` | The path to the certificate file (e.g., `cert.pem`). |
| `key` | `string` | The path to the private key file (e.g., `key.pem`). |

### **Routing Rules (`Rule`)**

Each `Rule` contains a **matcher** and a **handler**.

| Field | Type | Description |
| :--- | :--- | :--- |
| `name` | `string` | A unique name for the rule. |
| `type` | `string` | The matcher type: `substring`, `regex`, `timeout`, or `default`. |
| `tls_required` | `bool` | Whether this rule should only match TLS connections. If `true`, non-TLS connections will skip this rule. |
| `parameter` | `MatcherParameter` | The parameters required by the matcher. |
| `handler` | `HandlerConfig` | The handler configuration for a successful match. |

**`MatcherParameter`**

| Field | Type | Applicable Matcher | Description |
| :--- | :--- | :--- | :--- |
| `offset` | `int` | `substring` | The starting offset for matching. |
| `value` | `string` | `substring` | The substring to match against. |
| `pattern` | `string` | `regex` | The regular expression to match the data. |
| `timeout` | `int` | `timeout` | The timeout in seconds to wait for the first data packet. |

**`HandlerConfig`**

| Field | Type | Description |
| :--- | :--- | :--- |
| `name` | `string` | A unique name for the handler. |
| `type` | `string` | The handler type. Currently, only `passthrough` is supported. |
| `backend` | `string` | The backend service address, e.g., `localhost:22`. |
| `tls` | `BackendTLSConfig` | Whether to use TLS when connecting to the backend. |
| `timeout` | `int` | The read/write timeout for forwarded connections in seconds. |

### **Logging Configuration (`LoggingConfig`)**

| Field | Type | Description |
| :--- | :--- | :--- |
| `level` | `string` | The log level: `debug`, `info`, `warn`, `error`, etc. |
| `stderr` | `bool` | Whether to output logs to standard error. |
| `file` | `string` | The path to the log file. If empty, no file will be written. |
| `format` | `string` | The log format: `console` or `json`. |

Here is a detailed breakdown of the TCPMux configuration file, organized by **Matcher** and **Handler** types to help you better understand each part's purpose.

## Matcher

Matchers are responsible for deciding whether a connection matches a specific rule. Different types are available to suit various matching needs.

#### `substring`

This type of matcher searches for a specific substring within the first packet of data received from a connection.

  * **Use Case:** Ideal for matching protocol magic bytes or plaintext protocol headers.
  * **Configuration Parameters:**
      * `type: "substring"`: Specifies the matcher type.
      * `parameter.offset`: The byte offset in the data packet to begin the search.
      * `parameter.value`: The string to match.
  * **Example:** Matching the `SSH-` header of an SSH connection.
    ```yaml
    rules:
      - name: "ssh-rule"
        type: "substring"
        parameter:
          offset: 0
          value: "SSH-"
        # ... handler config
    ```

#### `regex`

This matcher type uses a regular expression to match the content of the data packet.

  * **Use Case:** Perfect for more complex pattern matching, such as HTTP request headers or any text-based protocol that follows a specific format.
  * **Configuration Parameters:**
      * `type: "regex"`: Specifies the matcher type.
      * `parameter.pattern`: The regular expression string, following `regexp2` syntax.
  * **Example:** Matching the start line of an HTTP request.
    ```yaml
    rules:
      - name: "http-rule"
        type: "regex"
        parameter:
          pattern: "^(GET|POST|PUT|DELETE) /"
        # ... handler config
    ```

#### `timeout`

This matcher activates when TCPMux is waiting for the first data packet. If no data is sent within the configured time, this rule is matched.

  * **Use Case:** Handling idle connections or forwarding unidentified, long-lived connections to a default backend (e.g., some TCP tunnels).
  * **Configuration Parameters:**
      * `type: "timeout"`: Specifies the matcher type.
      * `parameter.timeout`: The timeout in seconds to wait for data.
  * **Note:** It's common to configure only one `timeout` rule per configuration file.
  * **Example:** Forwarding a connection to a default backend if no data is received within 5 seconds.
    ```yaml
    rules:
      - name: "timeout-rule"
        type: "timeout"
        parameter:
          timeout: 5
        # ... handler config
    ```

#### `default`

This matcher catches any connection that doesn't match a preceding rule.

  * **Use Case:** Acts as a last resort, ensuring all unidentified traffic has a destination. It's often used to forward remaining traffic to a default web server or to simply close the connection.
  * **Configuration Parameters:**
      * `type: "default"`: Specifies the matcher type.
  * **Note:** Typically, you'll only have one `default` rule, and it should be placed at the end of your `rules` list.
  * **Example:**
    ```yaml
    rules:
      - name: "default-rule"
        type: "default"
        # ... handler config
    ```

## Handler

Handlers are responsible for processing matched connections. They define where the connection is forwarded and how it's handled.

#### `passthrough`

This is the only currently supported handler type. It copies incoming TCP connection data directly to a backend service, forwarding traffic bidirectionally.

  * **Use Case:** Transparently proxying TCP traffic to a backend service without any application-layer modifications.
  * **Configuration Parameters:**
      * `type: "passthrough"`: Specifies the handler type.
      * `backend`: The target backend service address in `host:port` format.
      * `timeout`: The read/write timeout in seconds for the forwarded connection.
      * `tls`: An optional sub-configuration to establish a TLS connection between TCPMux and the backend.
  * **Example:**
    ```yaml
    handler:
      name: "ssh-handler"
      type: "passthrough"
      backend: "localhost:22"
      timeout: 120
    ```
      * **Backend TLS Configuration (`handler.tls`):**
          * `enabled`: Whether to enable backend TLS.
          * `insecure_skip_verify`: Whether to skip backend certificate verification (not recommended for production).
          * `sni`: The SNI hostname to use when connecting to the backend.
          * `alpn`: A list of ALPN protocols to use when connecting to the backend.
  * **Example:** Forwarding TLS traffic to another backend service that also uses TLS.
    ```yaml
    handler:
      name: "https-handler"
      type: "passthrough"
      backend: "localhost:4430"
      tls:
        enabled: true
        insecure_skip_verify: false
        sni: "www.example.com"
      timeout: 60
    ```


## Example Configuration

Here is an example configuration that demonstrates how to route HTTP, HTTPS, and SSH traffic to different backends.

```yaml
listen:
  - "0.0.0.0:443"

tls:
  enabled: true
  config:
    - sni: "www.example.com"
      cert: "/path/to/www.example.com.cert"
      key: "/path/to/www.example.com.key"
    - sni: "api.example.com"
      cert: "/path/to/api.example.com.cert"
      key: "/path/to/api.example.com.key"
    - sni: "*" # Default certificate
      cert: "/path/to/default.cert"
      key: "/path/to/default.key"

rules:
  - name: "http-rule"
    type: "regex"
    tls_required: false # Non-TLS rule
    parameter:
      pattern: "^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH) /"
    handler:
      name: "http-handler"
      type: "passthrough"
      backend: "localhost:8080"
      timeout: 30

  - name: "https-rule"
    type: "regex"
    tls_required: true # TLS rule
    parameter:
      pattern: "Host: www\\.example\\.com"
    handler:
      name: "https-handler"
      type: "passthrough"
      backend: "localhost:4430"
      tls:
        enabled: true
        insecure_skip_verify: false
        sni: "www.example.com"
      timeout: 60

  - name: "ssh-rule"
    type: "substring"
    tls_required: false
    parameter:
      offset: 0
      value: "SSH-"
    handler:
      name: "ssh-handler"
      type: "passthrough"
      backend: "localhost:22"
      timeout: 120

  - name: "timeout-rule"
    type: "timeout"
    parameter:
      timeout: 5 # Matches this rule if no data is received within 5 seconds
    handler:
      name: "timeout-handler"
      type: "passthrough"
      backend: "localhost:9000"

  - name: "default-rule"
    type: "default"
    handler:
      name: "default-handler"
      type: "passthrough"
      backend: "localhost:8000"
      timeout: 30

logging:
  level: "info"
  stderr: true
  file: "tcpmux.log"
  format: "console"
```