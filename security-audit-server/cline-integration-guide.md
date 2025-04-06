# Enabling the Security Audit MCP Server with Cline/Roo Code

This guide explains how to enable the security audit MCP server with Cline/Roo Code.

## Configuration Steps

1. First, check if the Cline MCP settings directory exists:

```bash
ls -la ~/Library/Application\ Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/
```

2. If the directory doesn't exist, create it:

```bash
mkdir -p ~/Library/Application\ Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/
```

3. Check if the MCP settings file exists:

```bash
ls -la ~/Library/Application\ Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json
```

4. If the file doesn't exist or you want to create a new one, create it with the following content:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "node",
      "args": ["/path/to/security-audit-server/build/index.js"],
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

> **Note:** Replace `/path/to/security-audit-server` with the actual path to the security-audit-server directory on your system.

5. If the file already exists, you'll need to modify it to add the security audit MCP server configuration. Open the file in a text editor:

```bash
nano ~/Library/Application\ Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json
```

6. Add the security audit MCP server configuration to the `mcpServers` object. If the `mcpServers` object doesn't exist, create it. The final configuration should look something like this:

```json
{
  "mcpServers": {
    "existing-server-1": {
      // existing server configuration
    },
    "existing-server-2": {
      // existing server configuration
    },
    "security-audit": {
      "command": "node",
      "args": ["/path/to/security-audit-server/build/index.js"],
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

7. Save the file and restart Cline/Roo Code.

## Verifying the Integration

After restarting Cline/Roo Code, you can verify that the security audit MCP server is available by checking the Connected MCP Servers section in the system prompt. You should see the security-audit server listed there.

You can also verify the integration by using the security audit MCP server in a conversation:

```
I'd like to scan my project for security vulnerabilities. Can you help me with that?
```

Cline/Roo Code should now be able to use the security audit MCP server to scan your project for security vulnerabilities.

## Troubleshooting

If the security audit MCP server is not available in Cline/Roo Code after following these steps, check the following:

1. Make sure the path to the security audit MCP server is correct in the configuration file.
2. Make sure the security audit MCP server is built correctly by running `npm run build` in the security-audit-server directory.
3. Check the Cline/Roo Code logs for any errors related to the MCP server.
4. Make sure the `disabled` property is set to `false` in the configuration file.

## Using the Security Audit MCP Server

Once the security audit MCP server is enabled in Cline/Roo Code, you can use it to scan your projects for security vulnerabilities, check compliance with security standards, and generate security reports. See the main README.md file for more information on how to use the security audit MCP server.

### Example Usage

Here's an example of how to use the security audit MCP server to scan a codebase for security vulnerabilities:

```
use_mcp_tool({
  server_name: "security-audit",
  tool_name: "scan_code_security",
  arguments: {
    path: "/path/to/project",
    languages: ["javascript", "typescript"],
    scan_depth: "standard"
  }
})
```

This will scan the specified project for security vulnerabilities and return a summary of the results, including the number of vulnerabilities found and their severity levels.