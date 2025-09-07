# Controller

The `controller` module provides a set of HTTP and WebSocket endpoints for monitoring and managing the TCPMux server in real time.

### Fields

  - **`enabled`** (`bool`, **optional**): If `true`, the controller module will be activated. The server will listen on the specified address for API and WebSocket connections. Defaults to `false`.
  - **`listen`** (`string`, **optional**): The address and port for the controller to listen on (e.g., `localhost:9000`). This field is required if `enabled` is `true`.

### Endpoints

#### REST API

  - **`GET /connections`**

      * **Description**: Retrieves a list of all currently active TCP connections being handled by the server.
      * **Response**: A JSON array of objects, where each object represents a connection with details like ID, remote address, bytes transferred, and matched rule name.

  - **`POST /connections/:id/close`**

      * **Description**: Closes a specific active connection. The `:id` parameter should be replaced with the unique connection ID obtained from the `/connections` endpoint.
      * **Response**: A JSON object confirming the closure or an error message if the connection is not found.

  - **`GET /logs`**

      * **Description**: Returns the full content of the log file configured in the `logging` section. The content type is `text/plain`.
      * **Response**: The raw text content of the log file.

#### WebSocket

  - **`GET /ws/connections`**

      * **Description**: Establishes a WebSocket connection to receive a real-time stream of active connections. The server broadcasts a complete list of connections every second.
      * **Protocol**: WebSocket
      * **Data Format**: A JSON array of connection objects, identical to the `/connections` endpoint response, streamed at a fixed interval.

  - **`GET /ws/logs`**

      * **Description**: Establishes a WebSocket connection to stream new log entries as they are written to the log file.
      * **Protocol**: WebSocket
      * **Data Format**: A stream of individual log entries, each as a new line of text, following the format (`console` or `json`) specified in the logging configuration.

**Example**:

```yaml
controller:
  enabled: true
  listen: "localhost:9000"
```