# streamlit_app.py
import streamlit as st
import asyncio
import os
import sys
import time
import json # Make sure json is imported at the top
from typing import List, Dict, Any, Optional
import tempfile
import subprocess
# import nest_asyncio # Keep if you still need it elsewhere, but ideally not for the subprocess part

# nest_asyncio.apply()

# Configure page
st.set_page_config(page_title="Code Analysis Agent", page_icon="🔍", layout="wide")

class AnalysisAgent:
    """Agent that orchestrates code analysis through MCP middleware"""

    def __init__(self):
        # Store paths relative to this script file
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.middleware_path = os.path.join(self.script_dir, "mcp_middleware.py")
        self.python_executable = sys.executable # Assumes streamlit runs with the correct python
        self.results = {}
        self.status = "idle"
        self.error = None
        self.last_stderr = "" # Store stderr for debugging

    def analyze_files_subprocess(self, file_paths: List[str]) -> Dict[str, Any]:
        """
        Analyze files using a subprocess with improved error handling and logging.
        """
        self.status = "analyzing"
        self.error = None
        self.last_stderr = "" # Clear previous stderr

        # Define the path for the temporary script
        # Using tempfile is safer if multiple users might run this
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir=self.script_dir) as tf:
             temp_script_path = tf.name
             # --- Write the updated temporary script content (from Step 1) ---
             temp_script_content = f"""
import asyncio
import sys
import json
import os
import traceback
# Ensure mcp imports work in the subprocess environment
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

def log_stderr(message):
    print(f"TEMP_SCRIPT_LOG: {{message}}", file=sys.stderr, flush=True) # Add flush=True

async def analyze_files():
    if len(sys.argv) < 2:
        log_stderr("ERROR: No file paths provided via command line arguments.")
        print(json.dumps({{"success": False, "error": "No file paths provided to temp script."}}))
        return

    file_paths = sys.argv[1:]
    log_stderr(f"Received file paths: {{file_paths}}")

    # Get middleware path and python executable from environment
    middleware_path = os.environ.get("MCP_MIDDLEWARE_PATH")
    python_executable = os.environ.get("PYTHON_EXECUTABLE")

    if not middleware_path or not python_executable:
         log_stderr("ERROR: Middleware path or Python executable not provided (use env vars MCP_MIDDLEWARE_PATH, PYTHON_EXECUTABLE).")
         print(json.dumps({{"success": False, "error": "Middleware configuration missing in temp script environment."}}))
         return

    log_stderr(f"Middleware path: {{middleware_path}}")
    log_stderr(f"Python executable: {{python_executable}}")

    server_params = StdioServerParameters(
        command=python_executable,
        args=[middleware_path],
        env={{"PYTHONUNBUFFERED": "1"}} # Keep this
    )
    log_stderr("StdioServerParameters configured.")

    try:
        log_stderr("Attempting to connect using stdio_client...")
        async with stdio_client(server_params) as (read_stream, write_stream):
            log_stderr("stdio_client connected. Initializing session...")
            async with ClientSession(read_stream, write_stream) as session:
                await asyncio.wait_for(session.initialize(), timeout=30.0)
                log_stderr("Session initialized.")
                log_stderr("Calling 'analyze_files' tool...")
                result = await asyncio.wait_for(
                    session.call_tool("analyze_files", {{"file_paths": file_paths}}),
                    timeout=45.0 # Increased timeout for tool call
                )
                log_stderr("'analyze_files' tool call returned.")
                analysis_results = "\\\\n".join( # Escape backslashes for the f-string -> file write
                    content.text for content in result.content if hasattr(content, "text")
                )
                log_stderr("Analysis results extracted.")
                # IMPORTANT: Ensure this is the *very last* thing printed to stdout
                print(json.dumps({{"success": True, "analysis": analysis_results}}), flush=True)
                log_stderr("Successfully printed JSON result to stdout.")

    except asyncio.TimeoutError as e:
        log_stderr(f"ERROR: Timeout during MCP communication: {{e}}")
        print(json.dumps({{"success": False, "error": f"Timeout during MCP communication: {{e}}"}}))
    except Exception as e:
        log_stderr(f"ERROR: Exception during MCP communication: {{type(e).__name__}}: {{e}}")
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({{"success": False, "error": f"{{type(e).__name__}}: {{e}}"}}))

if __name__ == "__main__":
    try:
        asyncio.run(analyze_files())
    except Exception as e:
         log_stderr(f"FATAL ERROR in asyncio.run: {{type(e).__name__}}: {{e}}")
         print(json.dumps({{"success": False, "error": f"Fatal error running temp script: {{e}}"}}))

"""
             tf.write(temp_script_content)
             tf.flush() # Ensure content is written before subprocess starts

        try:
            # Prepare environment variables for the subprocess
            sub_env = os.environ.copy()
            sub_env["MCP_MIDDLEWARE_PATH"] = self.middleware_path
            sub_env["PYTHON_EXECUTABLE"] = self.python_executable
            sub_env["PYTHONPATH"] = os.environ.get("PYTHONPATH", "") # Ensure PYTHONPATH is inherited if needed

            st.info(f"Running analysis subprocess: {self.python_executable} {temp_script_path} ...")
            # Increase overall timeout, capture output, pass file paths as args
            process = subprocess.run(
                [self.python_executable, temp_script_path] + file_paths, # Pass files as arguments
                capture_output=True,
                text=True,
                timeout=90, # Increased overall timeout
                env=sub_env, # Pass the environment
                check=False # Don't raise exception on non-zero exit code, handle manually
            )

            self.last_stderr = process.stderr # Store stderr for debugging

            # --- Improved Output Parsing ---
            if process.stdout:
                # Try to find JSON in the last non-empty line of stdout
                last_line = process.stdout.strip().splitlines()[-1] if process.stdout.strip() else None
                if last_line:
                    try:
                        result_data = json.loads(last_line)
                        if isinstance(result_data, dict) and "success" in result_data:
                             if result_data["success"]:
                                 self.status = "completed"
                                 self.results = {
                                     "analysis": result_data.get("analysis", "No analysis data returned."),
                                     "files": file_paths
                                 }
                                 st.success("Analysis completed successfully.")
                                 return self.results
                             else:
                                 self.status = "error"
                                 self.error = result_data.get("error", "Unknown error from analysis script")
                                 st.error(f"Analysis script failed: {self.error}")
                                 return {"error": self.error}
                        else:
                            # Parsed JSON but not the expected format
                            self.status = "error"
                            self.error = "Received unexpected data format from analysis script."
                            st.error(self.error)
                            return {"error": self.error, "stdout": process.stdout, "stderr": process.stderr}
                    except json.JSONDecodeError:
                        self.status = "error"
                        self.error = "Could not parse analysis result (invalid JSON)."
                        st.error(self.error)
                        return {"error": self.error, "stdout": process.stdout, "stderr": process.stderr}
                else:
                     # stdout was empty or only whitespace
                     self.status = "error"
                     self.error = "Analysis script produced no standard output."
                     st.error(self.error)
                     return {"error": self.error, "stdout": process.stdout, "stderr": process.stderr}

            # Handle cases where stdout was empty but there might be errors
            elif process.returncode != 0:
                self.status = "error"
                self.error = f"Analysis process failed with exit code {process.returncode}."
                st.error(self.error)
                return {"error": self.error, "stderr": process.stderr}
            else:
                # No stdout, exit code 0 - unusual case
                self.status = "error"
                self.error = "Analysis script finished successfully but produced no output."
                st.warning(self.error) # Warning as it didn't technically fail
                return {"error": self.error, "stderr": process.stderr}

        except subprocess.TimeoutExpired:
            self.status = "error"
            self.error = f"Analysis timed out after 90 seconds"
            st.error(self.error)
            self.last_stderr = "Timeout occurred. No stderr captured."
            return {"error": self.error}
        except Exception as e:
            self.status = "error"
            self.error = f"Error running analysis subprocess: {str(e)}"
            st.error(f"Error running subprocess: {self.error}")
            # Attempt to capture any stderr available
            self.last_stderr = getattr(e, 'stderr', str(e))
            return {"error": self.error}
        finally:
            # Clean up temp script
            try:
                if os.path.exists(temp_script_path):
                    os.remove(temp_script_path)
            except Exception as e:
                st.warning(f"Could not remove temporary script {temp_script_path}: {e}")


# --- get_agent, save_uploaded_file --- (Keep as they are)
def get_agent():
    """Get or create the analysis agent"""
    if "agent" not in st.session_state:
        st.session_state.agent = AnalysisAgent()
    return st.session_state.agent

def save_uploaded_file(uploaded_file):
    """Save an uploaded file to a temporary directory and return the path"""
    # Using a single temp dir per run might be slightly cleaner
    if "temp_dir" not in st.session_state or not os.path.exists(st.session_state.temp_dir):
        st.session_state.temp_dir = tempfile.mkdtemp()

    file_path = os.path.join(st.session_state.temp_dir, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return file_path

def cleanup_temp_dir():
    if "temp_dir" in st.session_state and os.path.exists(st.session_state.temp_dir):
        import shutil
        try:
            shutil.rmtree(st.session_state.temp_dir)
            del st.session_state.temp_dir
        except Exception as e:
             st.warning(f"Could not clean up temp directory {st.session_state.temp_dir}: {e}")


def run_analysis(file_paths):
    """Run the analysis and update the UI"""
    agent = get_agent()
    # Display spinner during the blocking subprocess call
    with st.spinner(f"Analyzing {len(file_paths)} file(s)... Please wait (up to 90s)."):
        results = agent.analyze_files_subprocess(file_paths)

    # Display debug info if error occurred
    if agent.error:
        with st.expander("Show Debug Info (Stderr from analysis script)"):
            st.text(agent.last_stderr if agent.last_stderr else "No stderr captured.")

    return results

# --- display_code_analysis --- (Keep as it is)
def display_code_analysis(analysis_text):
    """Parse and display code analysis results"""
    st.markdown("---") # Separator
    try:
        # Try splitting based on known headers
        parts = analysis_text.split("===")
        code_part = None
        security_part = None

        for i, part in enumerate(parts):
            if "Code Analysis Results" in part and i + 1 < len(parts):
                code_part = parts[i+1].strip()
            elif "Security Analysis Results" in part and i + 1 < len(parts):
                security_part = parts[i+1].strip()

        if code_part:
            # If security part exists, remove it from the code part
            if security_part and "Security Analysis Results" in code_part:
                 code_part = code_part.split("Security Analysis Results")[0].strip("===").strip()

            st.subheader("📊 Code Analysis Results")
            st.text(code_part if code_part else "No specific code analysis results found.")
        else:
             st.subheader("📊 Code Analysis Results")
             st.text("No specific code analysis results header found.")


        if security_part:
            st.subheader("🔒 Security Analysis Results")
            st.text(security_part if security_part else "No specific security analysis results found.")
        else:
             st.subheader("🔒 Security Analysis Results")
             st.text("No specific security analysis results header found.")

        # Fallback: display raw if parsing fails badly
        if not code_part and not security_part and analysis_text:
             st.subheader("Raw Results")
             st.text(analysis_text)

    except Exception as e:
        st.error(f"Error displaying results: {e}")
        st.subheader("Raw Results")
        st.text(analysis_text if analysis_text else "Analysis text is empty.")

# --- Main Streamlit app ---
def main():
    st.title("🔍 Code Analysis Agent")

    # Use columns for layout
    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Upload Files")
        uploaded_files = st.file_uploader(
            "Choose code files for analysis",
            accept_multiple_files=True,
            key="file_uploader" # Add key for state management
        )

        agent = get_agent() # Initialize or get agent state

        # Display agent status
        st.markdown("---")
        st.markdown("### Agent Status")
        status_placeholder = st.empty() # Placeholder for dynamic status updates

        if agent.status == "idle":
            status_placeholder.info("Ready for analysis.")
        elif agent.status == "analyzing":
            status_placeholder.info("Analysis in progress...")
        elif agent.status == "completed":
            status_placeholder.success("Analysis completed.")
        elif agent.status == "error":
            status_placeholder.error(f"Error: {agent.error}")

        # Button appears only if files are uploaded
        if uploaded_files:
            if st.button("Analyze Files", key="analyze_button"):
                # Save uploaded files to temporary locations
                temp_file_paths = [save_uploaded_file(file) for file in uploaded_files]
                file_names = [file.name for file in uploaded_files]

                st.info(f"Starting analysis for: {', '.join(file_names)}")

                # Clear previous results display before running
                st.session_state.results_display = None

                # Run analysis
                results = run_analysis(temp_file_paths) # This now updates agent status internally

                # Store results for display in the other column
                st.session_state.results_display = results

                # Rerun to update the results column and status
                st.rerun()

    with col2:
        st.subheader("Analysis Results")
        results_placeholder = st.container() # Use a container for results area

        # Display results if available in session state
        if "results_display" in st.session_state and st.session_state.results_display:
            results = st.session_state.results_display
            with results_placeholder:
                if "error" in results:
                     # Error was already shown via st.error in run_analysis/agent method
                     # Optionally display raw output here too if needed
                     # if "stdout" in results: st.text(f"STDOUT:\n{results['stdout']}")
                     # if "stderr" in results: st.text(f"STDERR:\n{results['stderr']}")
                     pass
                elif "analysis" in results:
                    display_code_analysis(results["analysis"])
                    with st.expander("View Raw Analysis Text"):
                        st.text(results["analysis"])
                else:
                     st.warning("Analysis finished, but no results or error data found.")

    # Cleanup temp dir at the end of the script run if files were uploaded
    # This might run too early if analysis is long; consider session-based cleanup later if needed.
    # cleanup_temp_dir() # Temporarily disable automatic cleanup for debugging

if __name__ == "__main__":
    main()