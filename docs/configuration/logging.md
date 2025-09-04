# Logging

The `logging` section of the configuration file controls where and how log output is generated.

### Fields

- **`level`** (`string`, **required**): The minimum log level to display. Options are `debug`, `info`, `warn`, `error`, and `fatal`.
- **`stderr`** (`bool`, **optional**): If `true`, logs will be written to standard error. Defaults to `true`.
- **`file`** (`string`, **optional**): The path to a file where logs will be written.
- **`format`** (`string`, **optional**): The log format. Options are `console` (default) or `json`.

**Example**:

```yaml
logging:
  level: "debug"
  stderr: true
  file: "/var/log/tcpmux.log"
  format: "json"
```