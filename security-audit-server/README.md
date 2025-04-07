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
## Testing with Sample Vulnerabilities

The repository includes a sample file with intentional security vulnerabilities that you can use to test the security scanning capabilities:

### Testing with test-vulnerability.js

The `test-vulnerability.js` file contains several intentional security vulnerabilities:
1. Code injection via `eval()`
2. Command injection via string concatenation with `exec()`
3. Path traversal via unsanitized file paths
4. Regular Expression Denial of Service (ReDoS) vulnerability

To scan this file for security vulnerabilities:

1. **Start the Security Audit MCP server**:
   ```bash
   cd security-audit-server
   npm run build
   npm start
   ```

2. **Scan the file using the MCP tool**:
   ```
   use_mcp_tool({
     server_name: "security-audit",
     tool_name: "scan_code_security",
     arguments: {
       path: "security-audit-server/test-vulnerability.js",
       languages: ["javascript"],
       scan_depth: "deep"
     }
   })
   ```

3. **View the detailed scan results**:
   ```
   access_mcp_resource({
     server_name: "security-audit",
     uri: "security://vulnerabilities/{scan_id}"
   })
   ```
   Replace `{scan_id}` with the scan ID returned from the previous step.

4. **Expected Results**:
   The scan should identify at least the code injection vulnerability (use of `eval()`). The scanner uses ESLint with security rules to detect common security issues in JavaScript code.

### Extending the Security Rules

To detect more types of vulnerabilities, you can:

1. Modify the ESLint configuration in `src/integrations/eslint/eslint-security-config.json`
2. Add custom security rules in `src/integrations/eslint/custom-security-rules.js`
3. Update the Docker command in `src/integrations/eslint/eslint-scanner.ts` to include additional security plugins

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