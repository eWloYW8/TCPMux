# HTTP Matcher

The `http` matcher inspects the initial bytes of a connection to parse and match against an HTTP request's components.

### Configuration

  - **`methods`** (`[]string`, *optional*): A list of HTTP methods (e.g., `GET`, `POST`, `PUT`). The comparison is case-insensitive. The matcher returns `true` if any method in the list matches the request's method.
  - **`paths`** (`[]string`, *optional*, not recommended): A list of URL paths to match. Supports `*` as a wildcard. The matcher returns `true` if any path in the list matches the request's path.
  - **`hosts`** (`[]string`, *optional*): A list of `Host` headers to match. Supports `*` as a wildcard. The matcher returns `true` if any host in the list matches the request's `Host` header.


!!! warning
    Most web browsers and HTTP clients keep a single TCP connection open for a particular host to handle multiple requests, a process known as connection reuse.

    This is crucial to understand for the http matcher. Since TCPMux makes its routing decision based on the first request sent over a new connection, subsequent requests on that same reused connection will not be re-evaluated. Instead, they'll be sent to the same backend that the first request was routed to.

    For this reason, using **paths** or **methods** as the primary matching criterion might not work as expected if your client reuses connections. We highly recommend using the **hosts** parameter as the main rule for routing. If you need more granular routing based on paths or methods, consider using an application-level HTTP reverse proxy like **Nginx** or **Caddy**.

### Example

This rule matches `GET` or `POST` requests to any path on either `api.example.com` or `dev.api.example.com` hosts and directs them to a backend service.

```yaml
rules:
  - name: "http-api-rule"
    type: "http"
    parameter:
      methods:
        - "GET"
        - "POST"
      hosts:
        - "api.example.com"
        - "dev.api.example.com"
      paths:
        - "/v1/users/*"
        - "/v2/products/*"
    handler:
      name: "http-backend"
      type: "passthrough"
      parameter:
        backend: "127.0.0.1:8080"
```