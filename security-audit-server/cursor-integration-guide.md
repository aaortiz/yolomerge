# Enabling the Security Audit MCP Server with Cursor

This guide explains how to enable the security audit MCP server with the Cursor desktop application.

## Configuration Steps

1. First, check if the Claude desktop app configuration file exists:

```bash
ls -la ~/Library/Application\ Support/Claude/
```

2. If the directory doesn't exist, create it:

```bash
mkdir -p ~/Library/Application\ Support/Claude/
```

3. Check if the configuration file exists:

```bash
ls -la ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

4. If the file doesn't exist or you want to create a new one, create it with the following content:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "node",
      "args": ["/Users/nateaune/Documents/code/roocode_testing/security-audit-server/build/index.js"],
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

5. If the file already exists, you'll need to modify it to add the security audit MCP server configuration. Open the file in a text editor:

```bash
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
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
      "args": ["/Users/nateaune/Documents/code/roocode_testing/security-audit-server/build/index.js"],
      "disabled": false,
      "alwaysAllow": []
    }
  },
  // other existing configuration
}
```

7. Save the file and restart the Cursor application.

## Verifying the Integration

After restarting Cursor, you can verify that the security audit MCP server is available by using it in a conversation:

```
I'd like to scan my project for security vulnerabilities. Can you help me with that?
```

Cursor should now be able to use the security audit MCP server to scan your project for security vulnerabilities.

## Troubleshooting

If the security audit MCP server is not available in Cursor after following these steps, check the following:

1. Make sure the path to the security audit MCP server is correct in the configuration file.
2. Make sure the security audit MCP server is built correctly by running `npm run build` in the security-audit-server directory.
3. Check the Cursor logs for any errors related to the MCP server.
4. Make sure the `disabled` property is set to `false` in the configuration file.

## Using the Security Audit MCP Server

Once the security audit MCP server is enabled in Cursor, you can use it to scan your projects for security vulnerabilities, check compliance with security standards, and generate security reports. See the main README.md file for more information on how to use the security audit MCP server.