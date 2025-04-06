# mcp_middleware.py
import asyncio
import os
from typing import Dict, List
from contextlib import asynccontextmanager

from mcp.server.fastmcp import Context, FastMCP
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
# At the top of mcp_middleware.py
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/Users/jsc/saichandu_githhub/yolomerge/mcp_middleware.log"),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger("mcp_middleware")


# Get file paths from environment variable

class MCPServerConnection:
    """Manages a connection to an MCP server"""
    
    def __init__(self, name: str, command: str, args: List[str] = None):
        self.name = name
        self.command = command
        self.args = args or []
        self.session = None
    
    async def connect(self):
        """Establish connection to the MCP server"""
        logger.info(f"Connecting to server: {self.name}")
        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
        )
        
        try:
            logger.debug(f"Creating transport for {self.name}")
            self.transport_ctx = stdio_client(server_params)
            logger.debug(f"Entering transport context for {self.name}")
            self.read_stream, self.write_stream = await self.transport_ctx.__aenter__()
            logger.debug(f"Creating session for {self.name}")
            self.session = await ClientSession(self.read_stream, self.write_stream).__aenter__()
            logger.debug(f"Initializing session for {self.name}")
            await self.session.initialize()
            logger.info(f"Successfully connected to server: {self.name}")
            return self.session
        except Exception as e:
            logger.error(f"Error connecting to server {self.name}: {str(e)}")
            if hasattr(self, 'transport_ctx'):
                await self.transport_ctx.__aexit__(None, None, None)
            raise

    async def close(self):
        """Close the connection to the MCP server"""
        if self.session:
            await self.session.__aexit__(None, None, None)
        if hasattr(self, 'transport_ctx'):
            await self.transport_ctx.__aexit__(None, None, None)


class ServerConnections:
    """Manages connections to multiple MCP servers"""
    
    def __init__(self):
        self.connections: Dict[str, MCPServerConnection] = {}
    
    def register_server(self, name: str, command: str, args: List[str] = None):
        """Register a new MCP server"""
        self.connections[name] = MCPServerConnection(name, command, args)
    
    async def connect_all(self):
        """Connect to all registered MCP servers"""
        for conn in self.connections.values():
            await conn.connect()
    
    async def close_all(self):
        """Close all MCP server connections"""
        for conn in self.connections.values():
            await conn.close()
    
    def get_connection(self, name: str) -> MCPServerConnection:
        """Get a specific MCP server connection"""
        return self.connections.get(name)


# Create a context manager for server connections
# In server_connections_context
@asynccontextmanager
async def server_connections_context():
    """Context manager for server connections"""
    connections = ServerConnections()
    
    # Get absolute path to current script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    logger.info(f"Script directory: {script_dir}")
    
    # Register MCP servers with full paths
    connections.register_server(
        "code_analyzer", 
        "python3", 
        [os.path.join(script_dir, "code_analyzer_server.py")]
    )
    connections.register_server(
        "security_checker", 
        "python3", 
        [os.path.join(script_dir, "security_checker_server.py")]
    )
    
    # Try to connect to all servers, but don't fail if some can't connect
    try:
        connection_results = {}
        for name, conn in connections.connections.items():
            try:
                logger.info(f"Attempting to connect to server: {name}")
                await conn.connect()
                connection_results[name] = True
                logger.info(f"Successfully connected to server: {name}")
            except Exception as e:
                logger.error(f"Failed to connect to server {name}: {str(e)}")
                connection_results[name] = False
        
        # Log connection status
        logger.info(f"Connection results: {connection_results}")
        
        yield connections
    finally:
        logger.info("Closing all server connections")
        await connections.close_all()

# Create the middleware FastMCP server
@asynccontextmanager
async def middleware_lifespan(server: FastMCP):
    """Middleware lifespan that manages server connections"""
    async with server_connections_context() as connections:
        yield {"connections": connections}


# Initialize the MCP middleware server
middleware = FastMCP("MCP-Middleware", lifespan=middleware_lifespan)


@middleware.tool()
async def analyze_files(file_paths: List[str], ctx: Context) -> str:
    """
    Analyze files by sending them to code analyzer and security checker servers.
    
    Args:
        file_paths: List of file paths to analyze
        
    Returns:
        Combined analysis results
    """
    file_paths = file_paths or default_file_paths
    logger.info(f"Analyzing files: {file_paths}")
    
    # Get server connections from lifespan context
    connections = ctx.request_context.lifespan_context["connections"]
    
    # Validate file paths
    valid_paths = []
    for path in file_paths:
        if os.path.exists(path):
            valid_paths.append(path)
            logger.info(f"Valid file: {path}")
        else:
            logger.warning(f"File not found: {path}")
            ctx.warning(f"File not found: {path}")
    
    if not valid_paths:
        logger.error("No valid files found to analyze")
        return "Error: No valid files found to analyze"
    
    # Initialize results
    code_results = "Server not available or connection failed"
    security_results = "Server not available or connection failed"
    
    # Analyze code with the code analyzer server
    code_analyzer = connections.get_connection("code_analyzer")
    if code_analyzer and code_analyzer.session:
        try:
            logger.info("Sending files to code analyzer...")
            ctx.info("Sending files to code analyzer...")
            code_analysis = await code_analyzer.session.call_tool(
                "analyze_code", {"file_paths": valid_paths}
            )
            code_results = "\n".join(
                content.text for content in code_analysis.content if hasattr(content, "text")
            )
            logger.info("Code analysis completed successfully")
        except Exception as e:
            error_msg = f"Error during code analysis: {str(e)}"
            logger.error(error_msg)
            code_results = error_msg
    else:
        logger.warning("Code analyzer server not available")
    
    # Check security with the security checker server
    security_checker = connections.get_connection("security_checker")
    if security_checker and security_checker.session:
        try:
            logger.info("Sending files to security checker...")
            ctx.info("Sending files to security checker...")
            security_analysis = await security_checker.session.call_tool(
                "check_security", {"file_paths": valid_paths}
            )
            security_results = "\n".join(
                content.text for content in security_analysis.content if hasattr(content, "text")
            )
            logger.info("Security analysis completed successfully")
        except Exception as e:
            error_msg = f"Error during security analysis: {str(e)}"
            logger.error(error_msg)
            security_results = error_msg
    else:
        logger.warning("Security checker server not available")
    
    # Combine and return the results
    return f"""
=== Code Analysis Results ===
{code_results}

=== Security Analysis Results ===
{security_results}
"""

if __name__ == "__main__":
    middleware.run(transport="stdio")




# {
#   "mcpServers": {
#     "code-analysis-middleware": {
#       "command": "python3",
#       "args": ["/Users/jsc/saichandu_githhub/yolomerge/orchestrator_mcp/mcp_middleware.py"],
#       "env": {
#         "MCP_FILE_PATHS": "/Users/jsc/saichandu_githhub/yolomerge/orchestrator_mcp/example.py,/Users/jsc/saichandu_githhub/yolomerge/orchestrator_mcp/another_file.py"
#       }
#     }
#   }
# }