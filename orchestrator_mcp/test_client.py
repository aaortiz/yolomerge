# test_client.py
import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    if len(sys.argv) < 2:
        print("Usage: python test_client.py <file_path1> [<file_path2> ...]")
        return

    file_paths = sys.argv[1:]
    
    # Connect to middleware
    server_params = StdioServerParameters(
        command="python",
        args=["mcp_middleware.py"],
    )
    
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize the connection
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print(f"Available tools: {[tool.name for tool in tools.tools]}")
            
            # Call the analyze_files tool
            result = await session.call_tool(
                "analyze_files", {"file_paths": file_paths}
            )
            
            # Print the results
            for content in result.content:
                if hasattr(content, "text"):
                    print(content.text)

if __name__ == "__main__":
    asyncio.run(main())