# code_analyzer_server.py
from typing import List
from mcp.server.fastmcp import FastMCP
import logging # Add logging import
import sys
from typing import List
from mcp.server.fastmcp import FastMCP

# Configure basic logging for the analyzer itself
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - ANALYZER - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/Users/jsc/saichandu_githhub/yolomerge/analyzer.log", mode='w'), # Log to its own file
        logging.StreamHandler(sys.stderr) # Also log to stderr (might be captured by middleware later)
    ]
)
logger = logging.getLogger("code_analyzer")
logger.info("Code Analyzer Server script starting...") # Log start


# Create the code analyzer server
analyzer = FastMCP("Code-Analyzer")

@analyzer.tool()
async def analyze_code(file_paths: List[str]) -> str:
    """
    Analyze code in the provided files.
    
    Args:
        file_paths: List of file paths to analyze
        
    Returns:
        Analysis results
    """
    logger.info(f"Tool 'analyze_code' called with paths: {file_paths}") # Log tool calls
   
    results = []
    
    for path in file_paths:
        try:
            with open(path, 'r') as file:
                content = file.read()
                
                # In a real implementation, you would perform actual code analysis here
                # This is just a simple placeholder
                line_count = len(content.splitlines())
                char_count = len(content)
                
                results.append(f"File: {path}")
                results.append(f"  - Lines: {line_count}")
                results.append(f"  - Characters: {char_count}")
                
                # Simple complexity analysis
                if "import" in content:
                    results.append("  - Uses imports")
                if "class" in content:
                    results.append("  - Contains classes")
                if "def" in content:
                    results.append("  - Contains function definitions")
                
                results.append("")
            logger.info("Tool 'analyze_code' finished.")
        except Exception as e:
            results.append(f"Error analyzing {path}: {str(e)}")

    
    return "\n".join(results)

if __name__ == "__main__":
    try:
        logger.info("Attempting to run analyzer.run(transport='stdio')...")
        analyzer.run(transport="stdio") # This call blocks until the server stops
        logger.info("analyzer.run() finished.") # This likely won't be reached until shutdown
    except Exception as e:
        logger.exception("Error during analyzer.run()!") # Log exceptions during run