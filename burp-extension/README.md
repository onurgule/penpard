# PenPard MCP Connect - Burp Suite Extension

A custom Burp Suite extension that provides an MCP (Model Context Protocol) server accessible from Docker containers and external applications.

## Features

- **MCP SSE Server** on `0.0.0.0:9876` - Listens on all interfaces
- **Docker Compatible** - No localhost-only restrictions
- **Scanning Tools** - Start scans, retrieve issues
- **HTTP Requests** - Send requests through Burp
- **Proxy History** - Access intercepted traffic

## Building

```bash
cd burp-extension
./gradlew shadowJar
```

The built extension will be at: `build/libs/penpard-mcp-connect-1.0.0.jar`

## Installation

1. Open Burp Suite Professional
2. Go to **Extensions** → **Add**
3. Select the JAR file
4. Extension will start MCP server on port 9876

## MCP Tools

| Tool | Description |
|------|-------------|
| `start_scan` | Initiates active scan on target URL |
| `get_scanner_issues` | Retrieves found vulnerabilities |
| `send_http_request` | Sends HTTP request through Burp |
| `get_proxy_history` | Gets proxy history items |
| `get_scan_status` | Returns current scan status |
| `add_to_scope` | Adds URL to target scope |

## Usage with PenPard

Set the environment variable:
```bash
BURP_MCP_URL=http://YOUR_MACHINE_IP:9876
```

Or in `docker-compose.yml`:
```yaml
environment:
  - BURP_MCP_URL=http://host.docker.internal:9876
```

## Requirements

- Burp Suite Professional 2023.10+
- Java 17+
- Gradle 8.5+ (for building)
