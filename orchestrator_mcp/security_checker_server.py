# security_checker_server.py
from typing import List
from mcp.server.fastmcp import FastMCP

# Create the security checker server
security = FastMCP("Security-Checker")

@security.tool()
async def check_security(file_paths: List[str]) -> str:
    """
    Check files for security issues.
    
    Args:
        file_paths: List of file paths to check
        
    Returns:
        Security check results
    """
    results = []
    
    # Define some simple security patterns to check
    security_patterns = {
        "hardcoded_password": ["password =", "pwd =", "secret ="],
        "sql_injection": ["execute(", "executemany(", "raw_sql"],
        "unsafe_eval": ["eval(", "exec("],
        "command_injection": ["os.system(", "subprocess.call(", "subprocess.Popen("],
    }
    
    for path in file_paths:
        try:
            with open(path, 'r') as file:
                content = file.read()
                
                results.append(f"File: {path}")
                found_issues = False
                
                # Check for each security pattern
                for issue_type, patterns in security_patterns.items():
                    for pattern in patterns:
                        if pattern in content:
                            results.append(f"  - ISSUE: Possible {issue_type.replace('_', ' ')} detected!")
                            results.append(f"    Pattern: {pattern}")
                            found_issues = True
                
                if not found_issues:
                    results.append("  - No security issues detected.")
                
                results.append("")
        except Exception as e:
            results.append(f"Error checking {path}: {str(e)}")
    
    return "\n".join(results)

if __name__ == "__main__":
    security.run(transport="stdio")