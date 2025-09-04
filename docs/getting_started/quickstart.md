# Quick Start

### 1. Create a Configuration File

Create a file named `config.yaml` with the following content:

```yaml
listen:
  - "0.0.0.0:8080"
logging:
  level: "info"
rules:
  - name: "http-rule"
    type: "substring"
    parameter:
      offset: 0
      value: "GET"
    handler:
      name: "http-handler"
      type: "passthrough"
      parameter:
        backend: "127.0.0.1:8000"
```

### 2. Start a Backend Service

For this example, you need a simple web server running on `127.0.0.1:8000`. You can use Python for this:

```bash
python3 -m http.server 8000
```

### 3. Run TCPMux

Run the TCPMux server from your terminal:

```bash
./TCPMux --config config.yaml
```

TCPMux will now listen on port `8080`.

### 4. Test It

Open your browser or use `curl` to send a request to `localhost:8080`. The request should be successfully forwarded to your Python web server.

```bash
curl http://localhost:8080
```
