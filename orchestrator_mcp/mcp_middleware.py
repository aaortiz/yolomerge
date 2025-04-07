# mcp_middleware.py
import asyncio
import os
from typing import Dict, List, Optional # Added Optional
from contextlib import asynccontextmanager

from mcp.server.fastmcp import Context, FastMCP
from mcp import ClientSession, StdioServerParameters # Removed unused 'Optional' import here
from mcp.client.stdio import stdio_client
# At the top of mcp_middleware.py
import logging
import sys
import traceback # Import traceback for better error logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s', # Added funcName
    handlers=[
        logging.FileHandler("/Users/jsc/saichandu_githhub/yolomerge/mcp_middleware.log", mode='w'), # Use mode='w' to overwrite log each run for clarity
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger("mcp_middleware")

# Define default file paths (as requested for temporary fix)
# These will be used *instead* of the input arguments for now.
DEFAULT_FILES_FOR_TESTING = [
    "/Users/jsc/saichandu_githhub/yolomerge/orchestrator_mcp/example.py",
    "/Users/jsc/saichandu_githhub/yolomerge/orchestrator_mcp/another_file.py"
]


class MCPServerConnection:
    """Manages a connection to an MCP server"""

    def __init__(self, name: str, command: str, args: List[str] = None):
        self.name = name
        self.command = command
        self.args = args or []
        self.session: Optional[ClientSession] = None # Type hint session
        self.transport_ctx = None # Initialize transport_ctx
        self.read_stream = None
        self.write_stream = None

    async def connect(self):
        """Establish connection to the MCP server. Returns True on success, False on failure."""
        logger.info(f"Attempting to connect to server: {self.name}")
        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
        )

        try:
            logger.debug(f"Creating transport for {self.name} with cmd: '{self.command}' and args: {self.args}")
            self.transport_ctx = stdio_client(server_params)
            logger.debug(f"Entering transport context for {self.name}")
            # Use await with __aenter__ explicitly for clarity
            streams = await self.transport_ctx.__aenter__()
            if streams is None:
                 logger.error(f"Transport context __aenter__ returned None for {self.name}")
                 return False # Indicate failure
            self.read_stream, self.write_stream = streams

            logger.debug(f"Creating session for {self.name}")
            # Use await with __aenter__ explicitly for clarity
            self.session = await ClientSession(self.read_stream, self.write_stream).__aenter__()
            if self.session is None:
                logger.error(f"ClientSession __aenter__ returned None for {self.name}")
                await self.transport_ctx.__aexit__(None, None, None)
                return False

            logger.debug(f"Initializing session for {self.name}")
            try:
                # Add a timeout (e.g., 10 seconds)
                await asyncio.wait_for(self.session.initialize(), timeout=10.0)
                logger.info(f"Successfully connected and initialized session for server: {self.name}")
                return True # Indicate success
            except asyncio.TimeoutError:
                logger.error(f"Timeout occurred while initializing session for {self.name}!")
                # Attempt cleanup after timeout
                if self.session:
                    try:
                        await self.session.__aexit__(None, None, None) # Normal exit type
                    except Exception as exit_e:
                        logger.error(f"Error during session __aexit__ after timeout for {self.name}: {exit_e}")
                if self.transport_ctx:
                    try:
                        await self.transport_ctx.__aexit__(None, None, None) # Normal exit type
                    except Exception as exit_e:
                        logger.error(f"Error during transport __aexit__ after timeout for {self.name}: {exit_e}")
                self.session = None
                self.transport_ctx = None
                return False # Indicate failure due to timeout
        except Exception as e:
            # Handle other potential initialization errors
            logger.error(f"Error initializing session for {self.name}: {str(e)}")
            logger.debug(traceback.format_exc())
            # Ensure cleanup happens
            # (Cleanup code similar to the TimeoutError block - or refactor cleanup)
            if self.session: await self.session.__aexit__(*sys.exc_info()) # Pass exception info
            if self.transport_ctx: await self.transport_ctx.__aexit__(*sys.exc_info())
            self.session = None
            self.transport_ctx = None
            return False # Indicate failure

    async def close(self):
        """Close the connection to the MCP server"""
        logger.info(f"Closing connection to server: {self.name}")
        # Use explicit __aexit__ calls for clarity and error handling
        if self.session:
            try:
                # Passing None indicates normal exit
                await self.session.__aexit__(None, None, None)
                logger.debug(f"Session closed for {self.name}")
            except Exception as e:
                logger.error(f"Error closing session for {self.name}: {str(e)}")
                logger.debug(traceback.format_exc())
            finally:
                 self.session = None # Ensure session is marked as closed

        if self.transport_ctx:
            try:
                 # Passing None indicates normal exit
                await self.transport_ctx.__aexit__(None, None, None)
                logger.debug(f"Transport context exited for {self.name}")
            except Exception as e:
                logger.error(f"Error closing transport context for {self.name}: {str(e)}")
                logger.debug(traceback.format_exc())
            finally:
                self.transport_ctx = None # Ensure context is marked as closed
        logger.info(f"Connection closed for {self.name}")


class ServerConnections:
    """Manages connections to multiple MCP servers"""

    def __init__(self):
        self.connections: Dict[str, MCPServerConnection] = {}

    def register_server(self, name: str, command: str, args: List[str] = None):
        """Register a new MCP server"""
        if name in self.connections:
             logger.warning(f"Server '{name}' already registered. Overwriting.")
        self.connections[name] = MCPServerConnection(name, command, args)
        logger.info(f"Registered server: {name} (Cmd: {command}, Args: {args})")

    async def connect_all(self):
        """Connect to all registered MCP servers. Logs failures but continues."""
        connection_results = {}
        for name, conn in self.connections.items():
            logger.info(f"Initiating connection process for server: {name}")
            success = await conn.connect() # connect now returns True/False
            connection_results[name] = success
            if success:
                 logger.info(f"Successfully connected to server: {name}")
            else:
                 logger.error(f"Failed to connect to server {name}. Middleware will continue without it.")
        # Log final connection status summary
        logger.info(f"Connection attempt results: {connection_results}")


    async def close_all(self):
        """Close all MCP server connections"""
        logger.info("Closing all subordinate server connections...")
        # Use asyncio.gather to close connections concurrently
        await asyncio.gather(*(conn.close() for conn in self.connections.values()), return_exceptions=True)
        logger.info("Finished closing all subordinate server connections.")


    def get_connection(self, name: str) -> Optional[MCPServerConnection]: # Return Optional
        """Get a specific MCP server connection"""
        conn = self.connections.get(name)
        if conn:
             # Return the connection object only if the session is active
             # return conn if conn.session else None # Decided against this - tool should check session
             return conn
        return None

# Create a context manager for server connections
# In server_connections_context
@asynccontextmanager
async def server_connections_context():
    """Context manager for server connections"""
    connections = ServerConnections()

    try:
        # Use fully qualified paths
        code_analyzer_path = "/Users/jsc/saichandu_githhub/yolomerge/orchestrator_mcp/code_analyzer_server.py"
        security_checker_path = "/Users/jsc/saichandu_githhub/yolomerge/orchestrator_mcp/security_checker_server.py"
        python_path = "/Users/jsc/saichandu_githhub/yolomerge/.venv/bin/python3"
        
        logger.info(f"Starting code analyzer at: {code_analyzer_path}")
        connections.register_server(
            "code_analyzer",
            python_path,
            [code_analyzer_path]
        )
        
        logger.info(f"Starting security checker at: {security_checker_path}")
        connections.register_server(
            "security_checker", 
            python_path,
            [security_checker_path]
        )

        # Connect with proper timeout handling
        await connections.connect_all()
        yield connections
    except Exception as e:
        logger.error(f"Error in server connections: {e}")
        yield connections  # Still yield, but connections might be incomplete
    finally:
        await connections.close_all()
        
# Create the middleware FastMCP server
@asynccontextmanager
async def middleware_lifespan(server: FastMCP):
    """Middleware lifespan that manages server connections"""
    logger.info("Middleware lifespan starting...")
    try:
        async with server_connections_context() as connections:
            logger.info("Server connections context entered successfully.")
            yield {"connections": connections}
    except Exception as e:
        logger.critical(f"Failed to initialize middleware lifespan: {e}")
        logger.debug(traceback.format_exc())
        # If lifespan fails critically, yield an empty dict or raise to prevent server start
        yield {"connections": None} # Indicate failure state
    finally:
        logger.info("Middleware lifespan finished.")


# Initialize the MCP middleware server
middleware = FastMCP("MCP-Middleware", lifespan=middleware_lifespan)


@middleware.tool()
async def analyze_files(file_paths: List[str], ctx: Context) -> str:
    """
    Analyze files by sending them to code analyzer and security checker servers.
    Uses PREDEFINED file paths for testing, ignoring the 'file_paths' argument.

    Args:
        file_paths: List of file paths to analyze (CURRENTLY IGNORED)

    Returns:
        Combined analysis results
    """
    # --- TEMPORARY HARDCODING ---
    # Use predefined list instead of the input argument
    files_to_analyze = DEFAULT_FILES_FOR_TESTING
    logger.warning(f"analyze_files tool called, IGNORING input 'file_paths'. Using predefined list: {files_to_analyze}")
    # --- END TEMPORARY HARDCODING ---

    # Get server connections from lifespan context
    lifespan_data = ctx.request_context.lifespan_context
    if not lifespan_data or "connections" not in lifespan_data or lifespan_data["connections"] is None:
         error_msg = "Error: Middleware lifespan did not initialize connections correctly."
         logger.error(error_msg)
         return error_msg

    connections: ServerConnections = lifespan_data["connections"] # Type hint for clarity

    # Validate file paths (using the hardcoded list)
    valid_paths = []
    for path in files_to_analyze:
        abs_path = os.path.abspath(path) # Ensure absolute paths for checks
        if os.path.exists(abs_path):
            valid_paths.append(abs_path)
            logger.info(f"Found valid file for analysis: {abs_path}")
        else:
            warning_msg = f"Predefined file path not found: {abs_path}"
            logger.warning(warning_msg)
            # Also inform the client via context
            ctx.warning(warning_msg) # Use ctx.warning for non-fatal issues


    if not valid_paths:
        error_msg = "Error: No valid files found in the predefined list to analyze."
        logger.error(error_msg)
        return error_msg

    # Initialize results
    code_results = "Code analyzer server not available or connection failed during startup."
    security_results = "Security checker server not available or connection failed during startup."

    # --- Call Code Analyzer ---
# Inside analyze_files tool in mcp_middleware.py

# --- Call Code Analyzer ---
    code_analyzer = connections.get_connection("code_analyzer")
    if code_analyzer and code_analyzer.session:
        logger.debug(f"Code analyzer session appears active (Session ID: {code_analyzer.session if code_analyzer.session else 'N/A'}). Preparing to call tool.") # Added check
        try:
            tool_name = "analyze_code"
            tool_args = {"file_paths": valid_paths}
            logger.info(f"Sending files to code analyzer ({code_analyzer.name}) - Tool: {tool_name}, Args: {tool_args}")
            ctx.info("Sending files to code analyzer...")

            logger.debug(f"--- ABOUT TO AWAIT call_tool('{tool_name}')... ---") # Log before await
            code_analysis = await code_analyzer.session.call_tool(tool_name, tool_args)
            logger.debug(f"--- RETURNED FROM await call_tool('{tool_name}') ---") # Log after await

            # Safely extract text content
            text_parts = [content.text for content in code_analysis.content if hasattr(content, "text")]
            code_results = "\n".join(text_parts).strip()
            if not code_results:
                code_results = "[Code analyzer returned no text content]"
            logger.info("Code analysis completed successfully.")
            logger.debug(f"Code analysis raw result text: '{code_results}'") # Log result

        except Exception as e:
            # Log the specific exception during the call_tool attempt
            error_msg = f"Error during code analysis call: {str(e)}"
            logger.error(error_msg)
            # Log the full traceback for this specific error
            logger.error(f"Traceback for code analysis call error:\n{traceback.format_exc()}")
            code_results = f"ERROR calling code analyzer: {error_msg}"
            ctx.error(f"Failed to get results from code analyzer: {e}")
    elif code_analyzer:
        logger.warning("Code analyzer connection exists, but session is not active (likely failed during startup).")
    else:
        logger.warning("Code analyzer server was not registered or found.")


    # --- Call Security Checker ---
    security_checker = connections.get_connection("security_checker")
    if security_checker and security_checker.session: # Check both connection object and active session
        try:
            tool_name = "check_security"
            tool_args = {"file_paths": valid_paths}
            logger.info(f"Sending files to security checker ({security_checker.name}) - Tool: {tool_name}, Args: {tool_args}")
            ctx.info("Sending files to security checker...") # Inform client

            security_analysis = await security_checker.session.call_tool(tool_name, tool_args)

            # Safely extract text content
            text_parts = [content.text for content in security_analysis.content if hasattr(content, "text")]
            security_results = "\n".join(text_parts).strip() # Strip potential whitespace
            if not security_results: # Handle case where tool returns empty content
                 security_results = "[Security checker returned no text content]"
            logger.info("Security analysis completed successfully.")

        except Exception as e:
            error_msg = f"Error during security analysis call: {str(e)}"
            logger.error(error_msg)
            logger.debug(traceback.format_exc())
            security_results = f"ERROR calling security checker: {error_msg}"
            ctx.error(f"Failed to get results from security checker: {e}") # Inform client of error
    elif security_checker:
         logger.warning("Security checker connection exists, but session is not active (likely failed during startup).")
    else:
        logger.warning("Security checker server was not registered or found.")

    # Combine and return the results
    final_result = f"""
=== Code Analysis Results ===
{code_results}

=== Security Analysis Results ===
{security_results}
"""
    logger.info("Returning combined analysis results.")
    return final_result.strip() # Strip leading/trailing whitespace from the template


if __name__ == "__main__":
    logger.info("Starting MCP Middleware Server...")
    try:
        middleware.run(transport="stdio")
    except Exception as e:
         logger.critical(f"Middleware server failed to run: {e}")
         logger.debug(traceback.format_exc())
    finally:
         logger.info("MCP Middleware Server finished.")