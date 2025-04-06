import subprocess
import os

# Define the path to your repository
repo_path = "/Users/aaortiz/Documents/source/yolomerge"  # Replace with your actual path

# Change to the repository directory
os.chdir(repo_path)

# Execute the repomix command using Node.js
try:
    # Using npx to run the package from node_modules
    result = subprocess.run(
        ["npx", "repomix", "--remote", "https://github.com/aaortiz/yolomerge"],  # Replace with actual command and arguments
        check=True,
        capture_output=True,
        text=True
    )
    print("Command output:", result.stdout)
except subprocess.CalledProcessError as e:
    print("Error executing command:", e)
    print("Error output:", e.stderr)