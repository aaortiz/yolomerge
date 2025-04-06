# Security Audit MCP Server

A Model Context Protocol (MCP) server that provides comprehensive security auditing capabilities for codebases and live applications.
> **Note:** For instructions on enabling this MCP server with Cursor, see the [Cursor Integration Guide](./cursor-integration-guide.md).
>
> **Note:** For instructions on enabling this MCP server with Cline/Roo Code, see the [Cline Integration Guide](./cline-integration-guide.md).
> **Note:** For instructions on enabling this MCP server with Cursor, see the [Cursor Integration Guide](./cursor-integration-guide.md).

## Features

This MCP server provides the following security auditing capabilities across multiple languages and frameworks:

- **Static Code Analysis**: Scan code for security vulnerabilities across multiple languages (JavaScript/TypeScript, Python, Java)
- **Dynamic Application Security Testing**: Test live applications for security vulnerabilities
- **Dependency Vulnerability Scanning**: Check project dependencies for known vulnerabilities
- **Compliance Checking**: Verify compliance with security standards (OWASP Top 10, PCI DSS, HIPAA, GDPR)
- **Security Report Generation**: Generate comprehensive security reports in various formats

## Installation

The Security Audit MCP server needs to be installed and configured for use with your preferred AI assistant. Please refer to the integration guides above for detailed instructions on how to set up the server with Cline/Roo Code or Cursor.

## Usage

You can use the Security Audit MCP server through your AI assistant by invoking the available tools:

### Static Code Analysis

```
use_mcp_tool({
  server_name: "security-audit",
  tool_name: "scan_code_security",
  arguments: {
    path: "/path/to/project",
    languages: ["javascript", "typescript", "python", "java"],
    scan_depth: "standard"
  }
})
```

### Dependency Vulnerability Scanning

```
use_mcp_tool({
  server_name: "security-audit",
  tool_name: "scan_dependencies",
  arguments: {
    path: "/path/to/project",
    package_manager: "npm"
  }
})
```

### Dynamic Application Security Testing

```
use_mcp_tool({
  server_name: "security-audit",
  tool_name: "scan_live_application",
  arguments: {
    url: "https://example.com",
    scan_type: "passive",
    include_apis: true
  }
})
```

### Compliance Checking

```
use_mcp_tool({
  server_name: "security-audit",
  tool_name: "check_compliance",
  arguments: {
    target: "/path/to/project",
    standard: "owasp-top-10"
  }
})
```

### Security Report Generation

```
use_mcp_tool({
  server_name: "security-audit",
  tool_name: "generate_security_report",
  arguments: {
    scan_id: "scan-123456",
    format: "html"
  }
})
```

## Available Resources

The server also provides the following resources:

- `security://standards/owasp-top-10`: Information about the OWASP Top 10 security risks
- `security://vulnerabilities/{scan_id}`: Detailed information about vulnerabilities found in a scan
- `security://recommendations/{vulnerability_id}`: Remediation recommendations for specific vulnerabilities
- `security://compliance/{standard}`: Compliance information for specific security standards

You can access these resources using the `access_mcp_resource` tool:

```
access_mcp_resource({
  server_name: "security-audit",
  uri: "security://standards/owasp-top-10"
})
```

## Development

The Security Audit MCP server is built with TypeScript and uses the MCP SDK. The server integrates with various security tools through Docker containers.

### Project Structure

```
security-audit-server/
├── build/                  # Compiled JavaScript files
├── src/
│   ├── index.ts            # Main server entry point
│   ├── tools/              # Tool implementations
│   │   ├── static-analysis.ts
│   │   ├── dependency-scan.ts
│   │   ├── dynamic-testing.ts
│   │   ├── compliance-check.ts
│   │   └── report-generator.ts
│   ├── resources/          # Resource implementations
│   │   ├── vulnerabilities.ts
│   │   ├── recommendations.ts
│   │   └── compliance.ts
│   ├── integrations/       # Tool integrations
│   │   ├── eslint/
│   │   ├── bandit/
│   │   ├── spotbugs/
│   │   ├── dependency-check/
│   │   ├── zap/
│   │   └── nuclei/
│   └── utils/              # Utility functions
│       ├── docker.ts
│       ├── report.ts
│       └── config.ts
└── docker/                 # Docker configurations for tools
    ├── zap/
    ├── dependency-check/
    └── sonarqube/
```

### Building

To build the server, run:

```
npm run build
```

### Running

The server is automatically run by your AI assistant when needed. You can also run it manually:

```
npm start
```

## License

MIT