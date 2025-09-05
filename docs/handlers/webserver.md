# WebServer Handler

The `webserver` handler serves static files from a specified local directory, functioning as a simple, built-in web server. It's ideal for hosting simple websites, documentation, or providing access to files over HTTP. It includes support for basic authentication and configurable directory listing.

### Configuration

  * **`dir`** (`string`, **required**): The absolute or relative path to the local directory that will serve as the web server's root (e.g., `/var/www/html` or `./public`).
  * **`username`** (`string`, **optional**): If provided, the handler will require clients to present this username for basic authentication.
  * **`password`** (`string`, **optional**): The password to be used with the username for basic authentication.
  * **`index`** (`bool`, **optional**, default: `false`): Controls whether to allow directory listings for directories that don't contain an `index.html` file.
      * If `false` (or omitted), accessing such a directory will result in a `403 Forbidden` error.
      * If `true`, the contents of the directory will be displayed.

**Example**:

```yaml
handler:
  name: "my-static-site"
  type: "webserver"
  parameter:
    dir: "/var/www/my-site"
    username: "viewer"
    password: "simple-password"
    index: false
```