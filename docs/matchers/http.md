# HTTP 1.1 Matcher

The `http` matcher inspects the initial bytes of a connection to parse and match against an HTTP request's components.

### Configuration

  - **`methods`** (`[]string`, *optional*): A list of HTTP methods (e.g., `GET`, `POST`, `PUT`). The comparison is case-insensitive. The matcher returns `true` if any method in the list matches the request's method.
  - **`url_schemes`** (`[]string`, *optional*): A list of URL schemes (e.g., `http`, `https`) to match against the request's URL. Supports `*` as a wildcard. The comparison is case-insensitive. The matcher returns `true` if any scheme in the list matches.
  - **`url_hosts`** (`[]string`, *optional*): A list of hosts from the URL (e.g., `www.example.com:8080`) to match. Supports `*` as a wildcard. The comparison is case-insensitive. The matcher returns `true` if any host in the list matches.
  - **`url_paths`** (`[]string`, *optional*, not recommended): A list of URL paths to match. Supports `*` as a wildcard. The matcher returns `true` if any path in the list matches the request's path.
  - **`hosts`** (`[]string`, *optional*): A list of `Host` headers to match. This field corresponds directly to the `Host` header in the HTTP request. Supports `*` as a wildcard. The matcher returns `true` if any host in the list matches the request's `Host` header.

!!! note "Host vs. URL Host"
    The **`hosts`** parameter matches the **HTTP `Host` header**, which is crucial for **virtual hosting**. The **`url_hosts`** parameter, on the other hand, matches the **host component of the URL itself**.

!!! warning
    Most web browsers and HTTP clients keep a single TCP connection open for a particular host to handle multiple requests, a process known as connection reuse.

    This is crucial to understand for the http matcher. Since TCPMux makes its routing decision based on the first request sent over a new connection, subsequent requests on that same reused connection will not be re-evaluated. Instead, they'll be sent to the same backend that the first request was routed to.

    For this reason, using **`url_paths`**, **`methods`**, or **`url_schemes`** as the primary matching criterion might not work as expected if your client reuses connections. We highly recommend using the **`hosts`** or **`url_hosts`** parameters as the main rule for routing. If you need more granular routing based on paths or methods, consider using an application-level HTTP reverse proxy like **Nginx** or **Caddy**.


### Example

This rule matches `GET` or `POST` requests sent over `https` to any path on either `api.example.com` or `dev.api.example.com` hosts and directs them to a backend service.

```yaml
rules:
  - name: "http-api-rule"
    type: "http"
    parameter:
      methods:
        - "GET"
        - "POST"
      url_schemes:
        - "https"
      hosts:
        - "api.example.com"
        - "dev.api.example.com"
      url_paths:
        - "/v1/users/*"
        - "/v2/products/*"
    handler:
      name: "http-backend"
      type: "passthrough"
      parameter:
        backend: "127.0.0.1:8080"
```