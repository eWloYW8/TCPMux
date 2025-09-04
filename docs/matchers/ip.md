# IP Matcher

The `ip` matcher filters incoming connections based on their source IP address. It can act as either an allowlist (whitelist) or denylist (blacklist) using a list of CIDR blocks.

### Configuration

  - **`CIDRs`** (`string[]`, **required**): A list of IPv4 or IPv6 CIDR blocks to match against.
  - **`mode`** (`string`, **required**): Specifies whether the `CIDRs` list is an `allow` (whitelist) or `deny` (blacklist).


### Examples

#### Allowlist Example

This rule only allows connections originating from the `192.168.1.0/24` subnet. Connections from any other IP will not be matched by this rule.

```yaml
rules:
  - name: "internal-traffic-only"
    type: "ip"
    parameter:
      CIDRs:
        - "192.168.1.0/24"
      mode: "allow"
    handler:
      # ...
```


#### Denylist Example

This rule blocks all connections from the `10.0.0.0/8` private network. Any IP within that range will be matched, allowing you to handle them with a specific "block" handler.

```yaml
rules:
  - name: "block-ten-net"
    type: "ip"
    parameter:
      CIDRs:
        - "10.0.0.0/8"
      mode: "deny"
    handler:
      # ...
```