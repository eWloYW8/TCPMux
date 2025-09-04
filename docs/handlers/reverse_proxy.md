# Reverse Proxy Handler

The `reverse_proxy` handler acts as an HTTP reverse proxy, forwarding web traffic from the client to a specified backend server. It supports HTTP and WebSocket protocols and includes an optional basic authentication feature.

### Configuration

  - **`backend`** (`string`, **required**): The URL of the backend web server (e.g., `http://127.0.0.1:8000` or `https://backend.example.com`). The handler automatically determines whether to use TLS based on the URL's scheme.
  - **`username`** (`string`, **optional**): If provided, TCPMux will require clients to present this username for basic authentication.
  - **`password`** (`string`, **optional**): The password to be used with the username for basic authentication.

**Example**:

```yaml
handler:
  name: "my-web-server"
  type: "reverse_proxy"
  parameter:
    backend: "https://127.0.0.1:8443"
    username: "admin"
    password: "secure-password"
```
