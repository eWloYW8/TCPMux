# Rules

TCPMux's core functionality is defined by `rules`, which are processed in the order they appear in the configuration file.

### Rule Fields

Each rule is an object with the following fields:

- **`name`** (`string`, **required**): A unique name for the rule.
- **`type`** (`string`, **required**): The type of matcher to use. See the [Matchers section](../matchers/index.md) for available types.
- **`tls_required`** (`bool`, **optional**): If `true`, the rule will only be considered for connections that have completed a TLS handshake.
- **`parameter`** (`yaml.Node`, **required**): Parameters specific to the chosen `type`.
- **`handler`** (`HandlerConfig`, **required**): The handler to execute if the rule matches. See the [Handlers section](../handlers/index.md) for available types.

### Rule Matching Process

When a new connection is received, TCPMux iterates through the `rules` list. The first rule whose matcher returns `true` for the connection's initial data (or TLS handshake information) will be used to execute its corresponding handler.
