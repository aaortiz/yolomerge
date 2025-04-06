import subprocess
import os

# Define the path to your repository
repo_path = script_dir = os.path.dirname(os.path.abspath(__file__))

# Change to the repository directory
os.chdir(repo_path)

def extract_repo_name(repo_url):
    """
    Extract just the repository name from a GitHub URL.
    
    Args:
        repo_url (str): A GitHub repository URL (e.g., "https://github.com/username/repo")
        
    Returns:
        str: The repository name (e.g., "repo")
    """
    # Split the URL by '/'
    parts = repo_url.strip('/').split('/')
    
    # The repo name should be the last part of the URL
    # Handle cases where URL may or may not have trailing slash
    if parts[-1] == '':
        repo_name = parts[-2]
    else:
        repo_name = parts[-1]
    
    # Remove any potential .git suffix
    if repo_name.endswith('.git'):
        repo_name = repo_name[:-4]
        
    return repo_name

def run_repomix_on_repo(github_repo_url):
    """
    Execute the repomix command on a specified GitHub repository and save output to a file
    with the repo name.
    
    Args:
        github_repo_url (str): The GitHub repository URL (e.g., "https://github.com/username/repo")
        
    Returns:
        dict: A dictionary containing success status, output filename, stdout, and stderr
    """
    # Extract repo name for the output file
    repo_name = extract_repo_name(github_repo_url)
    output_filename = f"{repo_name}_analysis.txt"
    
    try:
        # Using npx to run the repomix package from node_modules
        result = subprocess.run(
            ["npx", "repomix", "--remote", github_repo_url, "--style", "plain", "--output", output_filename],
            check=True,
            capture_output=True,
            text=True
        )
        
        return {
            "success": True,
            "output_file": output_filename,
            "stdout": result.stdout,
            "stderr": None
        }
    except subprocess.CalledProcessError as e:
        error_filename = f"{repo_name}_error.txt"
        with open(error_filename, 'w') as f:
            f.write(e.stderr)
            
        print(f"Error executing command. Details saved to {error_filename}")
        
        return {
            "success": False,
            "output_file": error_filename,
            "stdout": None,
            "stderr": e.stderr
        }
    
if __name__ == "__main__":
    github_repo_url = "https://github.com/aaortiz/yolomerge"
    result = run_repomix_on_repo(github_repo_url)
