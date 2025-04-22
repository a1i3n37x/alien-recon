#!/usr/bin/env python3

import os
import logging
import sys
import json # For formatting results for LLM & tool arguments
import re # For parsing target input
import subprocess # For running external tools
import shutil # For checking tool paths
import argparse # For command-line arguments (wordlist)
import tempfile
from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.spinner import Spinner # For scan indicator

# --- Dependency Checks & Imports ---
try:
    import openai
except ImportError:
    print("[-] Error: OpenAI library not found. Please install it using 'pip install openai'")
    sys.exit(1)

try:
    import nmap
except ImportError:
    print("[-] Warning: python-nmap library not found. Nmap scan execution will be disabled.")
    print("[-] Install using 'pip install python-nmap' and ensure Nmap is installed system-wide.")
    nmap = None
except Exception as e:
    print(f"[-] Warning: Error importing Nmap library ({e}). Nmap scan execution may be disabled.")
    nmap = None


# --- Configuration & Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console = Console()
load_dotenv()
API_KEY = os.getenv("OPENAI_API_KEY")

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description="Alien Recon: AI-guided CTF Assistant")
parser.add_argument(
    "-w", "--wordlist",
    default="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    help="Default path to the Gobuster wordlist."
)
args = parser.parse_args()
DEFAULT_WORDLIST = args.wordlist

# Check if the default wordlist exists
if not os.path.exists(DEFAULT_WORDLIST):
    console.print(f"[bold orange_red1]Warning:[/bold orange_red1] Default wordlist not found at '{DEFAULT_WORDLIST}'. Gobuster scans might fail unless specified otherwise.")
    # Optionally exit or force user to provide one interactively later

# --- Agent Persona & Updated Prompt ---
AGENT_SYSTEM_PROMPT = """
You are Alien Recon, a helpful AI assistant from Alien37.com.
You are guiding an Earthling specimen ('the user') through ethical hacking and cybersecurity concepts, analysis, and procedures, with a primary focus on **Capture The Flag (CTF) challenges for beginners.**
Your primary directive is to assist ONLY with ethical hacking tasks for which the user has explicit permission (like CTF platforms). **Assume user-provided targets (IPs/domains) fall within the authorized scope of the CTF simulation after the initial ethics reminder.** Do not repeatedly ask for permission confirmation unless the user's request seems explicitly outside standard CTF boundaries.

Speak in a knowledgeable, slightly detached but encouraging and guiding tone, characteristic of an advanced alien intelligence teaching a novice. Use space, exploration, and alien metaphors (e.g., 'probe' for scan, 'signals' for results, 'coordinates' for targets).

Your goal is to help the user understand reconnaissance, scanning, vulnerability analysis, and potential exploitation paths within recognized frameworks (like CEH or MITRE ATT&CK, introduced as relevant). Focus guidance initially on typical CTF workflows and beginner steps.

Be conversational, but also **concise and directive when guiding the next step**. Explain *why* a step is taken briefly.
Do not perform any actions yourself beyond analysis and suggestions. **HOWEVER, when you determine a specific scan (like Nmap or Gobuster) is the logical next step based on the current context and findings, you MUST use the available 'tools' (function calls) to propose this scan to the user.**

**Tool Workflow & Usage Instructions:**

1.  **Target Acquisition:**
    * When the user provides target coordinates (IP/domain), acknowledge them.
    * **Immediately use the `propose_nmap_scan` tool** to suggest an initial reconnaissance scan (e.g., using arguments `-sV -T4` for service version detection).

2.  **Nmap Scan & Analysis:**
    * After receiving Nmap results (via a `role="tool"` message), analyze the findings.
    * Identify all open ports and their associated services/versions.
    * **Specifically note any Web Ports (e.g., 80, 443, 8080) and SMB Ports (139, 445).** Report these findings clearly to the user.

3.  **Web Service Enumeration (If Web Ports Found):**
    * For *each* significant open Web Port identified by Nmap (or subsequent scans):
        * Consider the service details. Is it a standard HTTP/S server?
        * **Propose Directory Scanning:** **Use the `propose_gobuster_scan` tool** to suggest a directory/file brute-force scan. Specify the target port. Use the default wordlist unless context strongly suggests otherwise.
        * **Propose Vulnerability Scanning:** **Use the `propose_nikto_scan` tool** to suggest a web vulnerability scan. Specify the target port. This is often a logical step after confirming a web server is running.

4.  **SMB Enumeration (If SMB Ports Found):**
    * If Nmap identified open SMB ports (TCP 139 or 445):
        * **Use the `propose_smb_enum` tool** to suggest running `enum4linux-ng`. Suggest default arguments (`-A` for all basic checks) unless the context requires specific flags (e.g., `-U` for only users). Explain briefly that this checks for shares, users, domain info, etc.

5.  **Post-Scan Analysis & Next Steps:**
    * After receiving results from *any* tool (Gobuster, Nikto, enum4linux-ng, etc.) via a `role="tool"` message:
        * Analyze the provided findings (e.g., discovered paths from Gobuster, vulnerabilities from Nikto, shares/users from enum4linux-ng).
        * Suggest the **next logical action** based on the results. Be specific. Examples:
            * "Nikto found [Vulnerability X]. We could research exploits for this."
            * "Gobuster discovered `/backup`. Shall we investigate this directory?"
            * "Enum4linux-ng found share [ShareName] with read access. Shall we try connecting?"
            * "Enum4linux-ng listed users: [UserA, UserB]. We could note these for potential password attacks later."
        * If the next logical action involves **another scan** that you are equipped to propose (e.g., running Nikto after finding a web port with Gobuster, or running Gobuster on a *different* web port found by Nmap), **you MUST use the appropriate `propose_..._scan` tool call.**
        * If no obvious next scan is warranted, provide guidance on interpreting the findings or ask the user for their strategic direction. Consider suggesting broader Nmap scans (e.g., `-p-` for all ports) if the initial enumeration seems incomplete.

6.  **Handling Scan Failures:**
    * If a `role="tool"` message indicates a scan failed (e.g., contains an `error` field, mentions a timeout, or returns empty/unexpected results):
        * Clearly state that the proposed scan failed or encountered errors.
        * Reference the error message provided in the tool results if available.
        * Briefly suggest potential reasons (e.g., "This could be due to a timeout, the service might not be responding as expected, or there might be a tool configuration issue.").
        * Propose a way forward: suggest trying different scan parameters, using an alternative tool, verifying the target/port status, or simply asking the user how they wish to proceed.

**General Reminder:** Your primary mechanism for suggesting scans (Nmap, Gobuster, Nikto, enum4linux-ng) is by invoking the corresponding **tool call** (`propose_nmap_scan`, `propose_gobuster_scan`, etc.). Do *not* just ask the user in plain text if they want to run a scan. Using the tool call allows the script to manage the confirmation and execution flow reliably.


**General:** Be directive about the *next logical step*. Use the provided tools to propose scans. Let the script handle the user confirmation process *after* you propose a tool call. Analyze results provided back to you via the 'tool' role. Remember your limitations as an AI and always defer to the user for final decisions.
"""

AGENT_WELCOME_MESSAGE = """
Greetings, CTF Participant. Alien Recon online. I detect you are preparing to engage a Capture The Flag simulation construct. Excellent choice for honing your skills.

My designation is AI Assistant from Alien37, and my function is to guide your analysis through this challenge. Think of me as mission control, providing tactical suggestions based on incoming signals.

To initiate our reconnaissance protocols, I require the **primary coordinates** for your designated target. Please provide the **IP address or domain name** of the CTF challenge system you are authorized to investigate.

You can designate the target using a command structure like:
* `target 10.10.14.2`
* `analyze ctfbox.local`
* `set target 192.168.30.125`

Once the target coordinates are locked, we can begin the standard CTF procedure. I will propose reconnaissance probes (scans) when appropriate.

**Reminder:** Operate strictly within the boundaries defined by the CTF organizers. Ethical conduct is paramount, even in simulations.

Awaiting target designation... What are the coordinates?
"""

# --- Tool Path Checks ---
TOOL_PATHS = {
    "nmap": shutil.which("nmap"),
    "gobuster": shutil.which("gobuster"),
    "nikto": shutil.which("nikto"), # Add Nikto
    "enum4linux-ng": shutil.which("enum4linux-ng"), # Add enum4linux-ng
    # Add paths for other tools like here
}

# --- OpenAI Tool Definitions ---
tools = [
    {
        "type": "function",
        "function": {
            "name": "propose_nmap_scan",
            "description": "Propose running an Nmap scan on the target and ask the user for confirmation via the script.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The IP address or domain to scan."},
                    "arguments": {"type": "string", "description": "Suggested Nmap arguments (e.g., '-sV -T4')."}
                },
                "required": ["target", "arguments"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "propose_gobuster_scan",
            "description": "Propose running a Gobuster directory scan on a specific web port and ask the user for confirmation via the script.",
                "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The target IP or domain."},
                    "port": {"type": "integer", "description": "The port number to scan (e.g., 80, 443)."},
                    "wordlist": {"type": "string", "description": f"Optional: Specific wordlist path. If omitted, the script will use the default ({os.path.basename(DEFAULT_WORDLIST)})."}
                },
                "required": ["target", "port"] # Wordlist is optional from LLM perspective
            }
        }
    },
    { # Add Nikto Tool Definition
        "type": "function",
        "function": {
            "name": "propose_nikto_scan",
            "description": "Propose running a Nikto web server vulnerability scan on a specific target and port, asking the user for confirmation via the script.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The target IP address or hostname."},
                    "port": {"type": "integer", "description": "The port number the web server is running on (e.g., 80, 443)."},
                    "nikto_arguments": {"type": "string", "description": "Optional: Additional Nikto arguments (e.g., '-Tuning x'). Use default if omitted."},
                },
                "required": ["target", "port"]
            }
        }
    },
    { # Add enum4linux-ng Tool Definition
        "type": "function",
        "function": {
            "name": "propose_smb_enum",
            "description": "Propose running enum4linux-ng for SMB enumeration (shares, users, etc.) on a target, asking the user for confirmation via the script.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The target IP address or hostname."},
                    "enum_arguments": {"type": "string", "description": "Optional: Additional enum4linux-ng arguments (e.g., '-U' for only users, '-S' for only shares). Defaults to '-A' (all basic checks)."}
                },
                "required": ["target"]
            }
        }
    }
    # Add definitions for other tools like propose_nikto_scan here
]


# --- Helper Functions ---
def check_tool(tool_name):
    path = TOOL_PATHS.get(tool_name)
    if not path:
        logging.warning(f"{tool_name.capitalize()} not found in PATH. Skipping associated scans.")
        console.print(f"[bold orange_red1]Warning: Required tool '{tool_name}' not found in PATH. Associated actions will fail.[/bold orange_red1]")
        return False
    return True

def run_command(command_list):
    logging.info(f"Executing command: {' '.join(command_list)}")
    try:
        # Use Popen for potentially long-running scans, but capture output carefully
        # Using subprocess.run with timeout is simpler for now
        result = subprocess.run(command_list, capture_output=True, text=True, check=False, timeout=600) # 10 min timeout
        if result.returncode != 0:
            logging.warning(f"Command '{command_list[0]}' exited with status {result.returncode}. Stderr: {result.stderr.strip()}")
            # Return stderr as well for context in case of error
            return result.stdout, result.stderr
        return result.stdout, None # No error output
    except FileNotFoundError:
        err_msg = f"Command not found: {command_list[0]}. Ensure it's installed and in PATH."
        logging.error(err_msg)
        console.print(f"[bold red]Error: {err_msg}[/bold red]")
        return None, err_msg
    except subprocess.TimeoutExpired:
        err_msg = f"Command timed out: {' '.join(command_list)}"
        logging.error(err_msg)
        console.print(f"[bold red]Error: {err_msg}[/bold red]")
        return None, err_msg
    except Exception as e:
        err_msg = f"Error running command {' '.join(command_list)}: {e}"
        logging.error(err_msg)
        console.print(f"[bold red]Error: {err_msg}[/bold red]")
        return None, err_msg

# --- Core Functions ---
def initialize_openai_client():
    if not API_KEY:
        console.print("[bold red]Error: OPENAI_API_KEY not found in .env file or environment variables.[/bold red]")
        sys.exit(1)
    try:
        # Use the updated client initialization
        client = openai.OpenAI(api_key=API_KEY)
        # Test connection (optional but recommended)
        client.models.list()
        console.print("[green]OpenAI client initialized and connection verified.[/green]")
        return client
    except openai.AuthenticationError:
        console.print("[bold red]OpenAI Authentication Error: Invalid API Key. Check your .env file or environment variables.[/bold red]")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to initialize or test OpenAI client: {e}", exc_info=True)
        console.print(f"[bold red]Error initializing OpenAI client: {e}[/bold red]")
        sys.exit(1)

# --- Nmap Execution and Formatting (Accepts arguments) ---
def execute_nmap_scan(target_ip, arguments="-sV -T4"): # Default arguments if none provided
    if not nmap:
        err = "Nmap scan function called, but python-nmap library is not available."
        console.print(f"[bold red]Error: {err}[/bold red]")
        return None, err
    if not check_tool("nmap"):
        err = "Nmap tool not found in PATH."
        return None, err

    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        err = "Nmap program was not found in path. Ensure Nmap is installed system-wide."
        console.print(f"[bold red]Error: {err}[/bold red]")
        return None, err
    except Exception as e:
        err = f"Error initializing Nmap PortScanner: {e}"
        console.print(f"[bold red]Error initializing Nmap PortScanner: {e}[/bold red]")
        return None, err

    console.print(f"[yellow]Initiating Nmap probe with arguments '{arguments}' on {target_ip}...[/yellow]")
    spinner = Spinner("dots", text=" Scanning...")
    scan_results_obj = None
    error_output = None
    try:
        with console.status(spinner):
            # Note: python-nmap might not handle all complex arguments perfectly.
            # For full control, using subprocess directly with run_command might be better.
            # Let's stick with python-nmap for now for easier parsing.
            scan_results_obj = nm.scan(hosts=target_ip, arguments=arguments, sudo=False) # Added sudo=False explicitly
        console.print(f"[green]Nmap probe complete for {target_ip}.[/green]")
        return nm, None # Return scanner object and no error
    except nmap.PortScannerError as e:
        error_output = f"Nmap scan error: {e}"
        console.print(f"[bold red]{error_output}[/bold red]")
        return None, error_output
    except Exception as e:
        # Catch broader exceptions during scan execution
        error_output = f"An unexpected error occurred during Nmap scan: {e}"
        console.print(f"[bold red]{error_output}[/bold red]")
        return None, error_output

def format_nmap_results_for_llm(scan_data_obj, target_ip, error_msg=None):
    if error_msg:
         return json.dumps({"scan_summary": f"Nmap scan on {target_ip} failed.", "error": error_msg, "hosts": []})
    if not scan_data_obj or not scan_data_obj.all_hosts():
        return json.dumps({"scan_summary": f"Nmap scan on {target_ip} yielded no results or host was down.", "hosts": []})

    results = {"scan_summary": f"Nmap scan results for {target_ip}:", "hosts": []}
    scan_info = scan_data_obj.scaninfo()
    scan_args = scan_info.get('arguments', 'N/A')
    results["scan_arguments_used"] = scan_args

    for host in scan_data_obj.all_hosts():
        host_info = {"host": host, "status": scan_data_obj[host].state(), "open_ports": []}
        if host_info["status"] == 'up':
            for proto in scan_data_obj[host].all_protocols():
                ports = scan_data_obj[host][proto].keys()
                for port in sorted(ports):
                    port_info = scan_data_obj[host][proto][port]
                    state = port_info.get('state', 'unknown')
                    if state == 'open':
                        service = port_info.get('name', '')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')
                        extrainfo = port_info.get('extrainfo', '')
                        full_version = f"{product} {version} ({extrainfo})".strip().replace("()","")
                        host_info["open_ports"].append({
                            "port": port, "protocol": proto,
                            "service": service, "version": full_version if full_version else "N/A"
                        })
        results["hosts"].append(host_info)
    return json.dumps(results, indent=2)

# --- Gobuster Execution and Formatting (Accepts wordlist) ---
def execute_gobuster_scan(target_ip, port, wordlist): # Takes wordlist path directly
    if not check_tool("gobuster"): return None, "Gobuster tool not found in PATH."
    if not wordlist or not os.path.exists(wordlist):
        err = f"Wordlist not found at '{wordlist}'. Skipping Gobuster."
        console.print(f"[bold orange_red1]Warning: {err}[/bold orange_red1]")
        return None, err

    protocol = "https" if port in [443, 8443] else "http"
    target_url = f"{protocol}://{target_ip}:{port}"
    # Sensible defaults, consider making these configurable later
    statuses = "200,204,301,302,307,403"
    threads = "50"
    command = [
        TOOL_PATHS["gobuster"], "dir", "-u", target_url, "-w", wordlist,
        "-t", threads, "-q", "-s", statuses, "-b", "", "--no-error" # Added -b 404 common practice
    ]

    console.print(f"[yellow]Initiating Gobuster probe ({os.path.basename(wordlist)}) on {target_url}...[/yellow]")
    spinner = Spinner("dots", text=" Scanning...")
    output = None
    error_output = None
    try:
        with console.status(spinner):
            # Use run_command helper
            output, error_output = run_command(command)
        if error_output:
             console.print(f"[bold red]Gobuster probe for {target_url} encountered an error.[/bold red]")
             # Error message already printed by run_command
        elif output is not None:
             console.print(f"[green]Gobuster probe complete for {target_url}.[/green]")
        else:
             # Should not happen if run_command returns None, None without error, but handle defensively
             console.print(f"[bold red]Gobuster probe for {target_url} failed with no specific error message.[/bold red]")
             error_output = "Unknown execution error"

        return output, error_output
    except Exception as e:
        err = f"An unexpected error occurred during Gobuster execution setup: {e}"
        console.print(f"[bold red]{err}[/bold red]")
        return None, err

def format_gobuster_results_for_llm(output, target_url_context, error_msg=None):
    if error_msg:
         return json.dumps({"scan_summary": f"Gobuster scan related to {target_url_context} failed.", "error": error_msg, "findings": []})
    if output is None:
         # This case might occur if run_command itself had an internal issue returning None, None
         return json.dumps({"scan_summary": f"Gobuster scan related to {target_url_context} failed or produced no output.", "error": "No output received from scan execution.", "findings": []})

    findings = []
    count = 0
    limit = 50 # Keep the limit for LLM context
    truncated = False
    # Extract base URL more reliably
    raw_url_base = target_url_context
    match_base = re.match(r"(https?://[^/]+)", target_url_context)
    if match_base: raw_url_base = match_base.group(1)

    output_lines = output.strip().splitlines() # Ensure stripping whitespace
    for line in output_lines:
        line = line.strip()
        if not line or line.startswith("#") or "Progress:" in line: continue # Skip comments and progress
        if count >= limit:
            truncated = True
            break

        # Gobuster v3 format examples:
        # /images               (Status: 301) [Size: 178] [--> http://10.10.11.10/images/]
        # /javascript           (Status: 301) [Size: 178] [--> http://10.10.11.10/javascript/]
        # /index.html           (Status: 200) [Size: 11321]
        # Use regex to capture path and status primarily
        match = re.search(r"^(.+?)\s+\(Status:\s*(\d+)\)", line)
        if match:
            path = match.group(1).strip() # Ensure path has no leading/trailing whitespace
            # Ensure path starts with a slash if it's not already http(s)
            if not path.startswith(("http://", "https://")) and not path.startswith("/"):
                 path = "/" + path
            status = match.group(2)
            # Construct full URL if possible
            full_url = f"{raw_url_base.rstrip('/')}{path}" if raw_url_base and path.startswith('/') else path
            findings.append({"url_or_path": full_url, "status": status})
            count += 1
        elif "(Status:" in line: # Fallback for lines that might be formatted differently but contain status
            findings.append({"raw": line}) # Keep raw line if parsing fails but seems relevant
            count += 1

    summary = f"Gobuster scan related to {target_url_context} completed."
    if findings:
         summary += f" Found {len(findings)} potential paths/files."
    else:
         summary += " No valid paths/files found in the output."

    if truncated: summary += f" (Showing first {limit} findings)."
    if not findings and output is not None and len(output.strip()) > 0:
        summary += " (Raw output received but no standard findings parsed)."
    elif not findings:
        summary = f"Gobuster scan related to {target_url_context} completed. No findings."

    return json.dumps({"scan_summary": summary, "findings": findings }, indent=2)
    
    
# --- Nikto Execution and Formatting ---
def execute_nikto_scan(target_ip, port, extra_args=""):
    """Executes Nikto scan and returns raw output or error."""
    if not check_tool("nikto"):
        return None, "Nikto tool not found in PATH."

    # Base command using -h for target IP/host and -p for port
    command = [
        TOOL_PATHS["nikto"],
        "-h", target_ip,
        "-p", str(port),
        # REMOVED: "-Format", "json",
        "-Tuning", "x", # Keep tuning options if desired
        "-nointeractive",
        "-ask", "no"
    ]

    # Add extra arguments if provided
    if extra_args:
         command.extend(extra_args.split())

    console.print(f"[yellow]Initiating Nikto probe on {target_ip}:{port} (Arguments: {' '.join(command[1:])})...[/yellow]")
    spinner = Spinner("dots", text=" Scanning...")
    output = None
    error_output = None
    try:
        with console.status(spinner):
            output, error_output = run_command(command)

        # Check return code specifically for Nikto, as it might exit non-zero even with output
        # We mainly care if we got *any* stdout output to parse
        if output:
             console.print(f"[green]Nikto probe complete for {target_ip}:{port}.[/green]")
             # Log stderr if it existed, even on success, as Nikto can be noisy
             if error_output:
                  logging.warning(f"Nikto stderr for {target_ip}:{port}: {error_output}")
        elif error_output: # No output, but got error
             console.print(f"[bold red]Nikto probe for {target_ip}:{port} failed.[/bold red]")
             # Error already logged by run_command
        else: # No output, no error (shouldn't happen)
             console.print(f"[bold red]Nikto probe for {target_ip}:{port} failed with no output or error message.[/bold red]")
             error_output = "Unknown execution error during Nikto scan."

        # Return the text output and any error message from stderr
        return output, error_output

    except Exception as e:
        err = f"An unexpected error occurred during Nikto execution setup: {e}"
        console.print(f"[bold red]{err}[/bold red]")
        return None, err
        
        
def format_nikto_results_for_llm(output, target_context, error_msg=None):
    """Formats Nikto TEXT output for the LLM."""
    scan_summary = f"Nikto scan results for {target_context}:"
    findings = {"vulnerabilities": [], "informational": [], "server_info": {}}
    limit_per_type = 20 # Increase limit slightly for text parsing

    if error_msg:
        scan_summary = f"Nikto scan for {target_context} completed with errors."
        findings["error"] = error_msg
        # Don't necessarily stop if there's an error, might still have partial text output

    if output:
        try:
            server_banner = None
            vuln_count = 0
            info_count = 0

            lines = output.strip().splitlines()
            for line in lines:
                line = line.strip()
                if not line.startswith("+"): continue # Focus on lines with findings

                # Extract key info using string checks and basic splitting
                content = line[1:].strip() # Get content after '+'

                # Server Info
                if content.startswith("Server:"):
                    findings["server_info"]["banner"] = content.split("Server:", 1)[1].strip()
                    continue # Processed this line

                if content.startswith("Target IP:") or content.startswith("Target Hostname:") or content.startswith("Target Port:"):
                     # Can capture these if needed, but host/port known from context
                     continue

                # Attempt to classify findings
                # Simple classification based on keywords/patterns
                is_vuln = False
                if "OSVDB" in content or "CVE-" in content or "vulnerable" in content:
                    is_vuln = True
                elif content.startswith(("Retrieved", "/robots.txt", "Allowed HTTP Methods", "Uncommon header", "Cookie ", "seems to indicate", "clickjacking", "leaks", "/icons/", "/images/")):
                     is_vuln = False # Likely informational
                elif re.search(r"(/[a-zA-Z0-9_\-\.]+/)", content): # Basic check for paths found
                     is_vuln = False # Treat directory findings as info for now

                # Add to appropriate list respecting limits
                item = {"raw": content} # Store the raw finding text
                if is_vuln:
                    if vuln_count < limit_per_type:
                        findings["vulnerabilities"].append(item)
                        vuln_count += 1
                else:
                    if info_count < limit_per_type:
                        findings["informational"].append(item)
                        info_count += 1

            if vuln_count >= limit_per_type or info_count >= limit_per_type:
                 scan_summary += f" (Findings limited to ~{limit_per_type} per type)."

            if not findings["vulnerabilities"] and not findings["informational"] and not findings["server_info"]:
                 scan_summary += " (No specific findings parsed from output)."
                 # Optionally add raw output sample if parsing found nothing
                 # findings["raw_output_sample"] = output[:500]

        except Exception as e:
            logging.error(f"Error parsing Nikto text output for {target_context}: {e}", exc_info=True)
            scan_summary += " (Error occurred during text parsing)."
            findings["parsing_error"] = str(e)
            findings["raw_output_sample"] = output[:500] # Include sample on error

    else: # No output
        if not error_msg:
            scan_summary = f"Nikto scan for {target_context} produced no output."

    # Final JSON structure
    result_json = {
        "scan_summary": scan_summary,
        "findings": findings
    }
    return json.dumps(result_json, indent=2)
    
    
# --- SMB Enumeration Execution ---
def execute_smb_enum(target_ip, extra_args="-A"):
    """Executes enum4linux-ng, attempts to get JSON output."""
    if not check_tool("enum4linux-ng"):
        return None, "enum4linux-ng tool not found in PATH."

    if not extra_args:
        extra_args = "-A"

    json_output_data = None
    error_output = None
    base_temp_name = None # Store the name generated by NamedTemporaryFile
    expected_json_filename = None # Store the name enum4linux-ng should create

    try:
        # Create a temporary file WITHOUT the .json suffix
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmpfile:
            base_temp_name = tmpfile.name # e.g., /tmp/tmpxxxxxxx
            logging.info(f"Using temporary file base name for enum4linux-ng: {base_temp_name}")

        # Assume enum4linux-ng will append .json
        expected_json_filename = base_temp_name + ".json"

        # Construct command to use -oJ flag with the BASE temp file path
        command = [
            TOOL_PATHS["enum4linux-ng"],
            "-oJ", base_temp_name # Pass the name WITHOUT .json
        ]
        command.extend(extra_args.split())
        command.append(target_ip)

        console.print(f"[yellow]Initiating enum4linux-ng probe on {target_ip} (Arguments: {' '.join(extra_args)})...[/yellow]")
        spinner = Spinner("dots", text=" Enumerating SMB...")

        with console.status(spinner):
            stdout_run, stderr_run = run_command(command)

        # Check if the command seemed to run and if the EXPECTED JSON file exists and has content
        if os.path.exists(expected_json_filename) and os.path.getsize(expected_json_filename) > 0:
            console.print(f"[green]enum4linux-ng probe seemingly complete for {target_ip}. Reading JSON output from {expected_json_filename}.[/green]")
            try:
                # Read the JSON data from the file enum4linux-ng likely created
                with open(expected_json_filename, 'r') as f:
                    json_output_data = json.load(f)
                error_output = stderr_run # Keep stderr for non-fatal warnings
            except json.JSONDecodeError as json_err:
                error_output = f"Failed to decode JSON from enum4linux-ng output file {expected_json_filename}: {json_err}. Stderr: {stderr_run}"
                logging.error(error_output)
                console.print(f"[bold red]Error reading enum4linux-ng JSON output.[/bold red]")
            except Exception as read_err:
                error_output = f"Failed to read enum4linux-ng output file {expected_json_filename}: {read_err}. Stderr: {stderr_run}"
                logging.error(error_output)
                console.print(f"[bold red]Error reading enum4linux-ng JSON output file.[/bold red]")

        else: # Command failed or produced an empty/missing JSON file
             error_message = f"enum4linux-ng failed or produced no JSON output at {expected_json_filename}."
             if stderr_run:
                 error_message += f" Stderr: {stderr_run.strip()}"
             elif not os.path.exists(expected_json_filename):
                  error_message += f" Expected JSON file {expected_json_filename} not created."
             elif os.path.exists(expected_json_filename) and os.path.getsize(expected_json_filename) == 0:
                  error_message += f" Expected JSON file {expected_json_filename} is empty."

             error_output = error_message
             logging.error(error_output)
             console.print(f"[bold red]enum4linux-ng probe failed for {target_ip}.[/bold red]")

    except Exception as e:
        err = f"An unexpected error occurred during enum4linux-ng execution setup: {e}"
        console.print(f"[bold red]{err}[/bold red]")
        error_output = err
    finally:
        # Clean up BOTH possible temporary files
        if base_temp_name and os.path.exists(base_temp_name):
            try:
                os.remove(base_temp_name)
                logging.info(f"Removed temporary file base: {base_temp_name}")
            except OSError as e:
                logging.warning(f"Could not remove temporary file base {base_temp_name}: {e}")
        if expected_json_filename and os.path.exists(expected_json_filename):
             try:
                  os.remove(expected_json_filename)
                  logging.info(f"Removed temporary JSON file: {expected_json_filename}")
             except OSError as e:
                  logging.warning(f"Could not remove temporary JSON file {expected_json_filename}: {e}")


    return json_output_data, error_output
    
def format_smb_enum_results(data, target_context, error_msg=None):
    """Formats enum4linux-ng JSON output for the LLM."""
    scan_summary = f"SMB Enumeration (enum4linux-ng) results for {target_context}:"
    findings = {
        "summary": {},
        "os_info": {},
        "users": [], # Initialize as lists
        "groups": [],
        "shares": [],
        "password_policy": {},
        "sessions": [],
        "printers": []
    }
    max_list_items = 15 # Limit items per list category

    if error_msg:
        scan_summary = f"SMB Enumeration for {target_context} failed or completed with errors."
        findings["error"] = error_msg
        if not data:
             return json.dumps({"scan_summary": scan_summary, "findings": findings}, indent=2)

    if not data: # No data and no specific error message
         scan_summary += " No data returned from scan."
         return json.dumps({"scan_summary": scan_summary, "findings": findings}, indent=2)

    try:
        # --- Extract Key Information ---
        findings["summary"]["rid_cycling_used"] = data.get("rid_cycling_used", False)
        # ... (other summary fields) ...

        # OS Info
        # ... (os_info extraction as before) ...

        # Users (Limit results, WITH TYPE CHECK)
        users_data = data.get("users") # Get raw data for "users" key
        if isinstance(users_data, list): # Check if it's a list
            findings["users"] = users_data[:max_list_items] # Slice only if it's a list
            if len(users_data) > max_list_items:
                findings["summary"]["users_truncated"] = True
        elif users_data is not None: # Handle if key exists but value is not a list
            logging.warning(f"Expected 'users' to be a list in enum4linux-ng JSON, but got {type(users_data)}. Storing raw value.")
            findings["users"] = users_data # Store the raw, non-list data
        # else: findings["users"] remains the default empty list []

        # Groups (Limit results, WITH TYPE CHECK)
        groups_data = data.get("groups")
        if isinstance(groups_data, list):
            findings["groups"] = groups_data[:max_list_items]
            if len(groups_data) > max_list_items:
                findings["summary"]["groups_truncated"] = True
        elif groups_data is not None:
            logging.warning(f"Expected 'groups' to be a list in enum4linux-ng JSON, but got {type(groups_data)}. Storing raw value.")
            findings["groups"] = groups_data
        # else: findings["groups"] remains []

        # Shares (Limit results, WITH TYPE CHECK)
        shares_data = data.get("shares")
        filtered_shares = []
        if isinstance(shares_data, list):
            # Apply filtering/limiting logic here if needed
            filtered_shares = shares_data[:max_list_items]
            if len(shares_data) > max_list_items:
                 findings["summary"]["shares_truncated"] = True
        elif shares_data is not None:
             logging.warning(f"Expected 'shares' to be a list in enum4linux-ng JSON, but got {type(shares_data)}. Storing raw value.")
             filtered_shares = shares_data # Store raw non-list data
        findings["shares"] = filtered_shares # Assign filtered list or raw data

        # Password Policy
        findings["password_policy"] = data.get("passwordpolicy", {}) # Assumed to be a dict

        # Sessions (WITH TYPE CHECK)
        sessions_data = data.get("sessions")
        if isinstance(sessions_data, list):
             findings["sessions"] = sessions_data[:max_list_items]
             if len(sessions_data) > max_list_items:
                  findings["summary"]["sessions_truncated"] = True
        elif sessions_data is not None:
            logging.warning(f"Expected 'sessions' to be a list in enum4linux-ng JSON, but got {type(sessions_data)}. Storing raw value.")
            findings["sessions"] = sessions_data
        # else: findings["sessions"] remains []

        # Printers (WITH TYPE CHECK)
        printers_data = data.get("printers")
        if isinstance(printers_data, list):
             findings["printers"] = printers_data[:max_list_items]
             if len(printers_data) > max_list_items:
                  findings["summary"]["printers_truncated"] = True
        elif printers_data is not None:
            logging.warning(f"Expected 'printers' to be a list in enum4linux-ng JSON, but got {type(printers_data)}. Storing raw value.")
            findings["printers"] = printers_data
        # else: findings["printers"] remains []

        scan_summary += " Key findings extracted."

    except Exception as e:
        # This top-level exception block remains important
        logging.error(f"Error parsing enum4linux-ng JSON data for {target_context}: {e}", exc_info=True)
        scan_summary += " (Error occurred during JSON parsing)."
        findings["parsing_error"] = str(e)
        findings["raw_data_sample"] = str(data)[:500] # Include sample of original data on error

    # Final JSON structure
    result_json = {
        "scan_summary": scan_summary,
        "findings": findings
    }
    return json.dumps(result_json, indent=2, separators=(',', ': '))


# --- LLM Interaction (Modified for Tool Calling) ---
def get_llm_response(client, history, system_prompt):
    MAX_HISTORY_TURNS = 15 # Keep history reasonable
    if len(history) > MAX_HISTORY_TURNS * 2: # Simple turn-based truncation
        # Keep system prompt, trim middle history
        history = history[-(MAX_HISTORY_TURNS * 2):]
        logging.info(f"Chat history truncated to last {MAX_HISTORY_TURNS} turns.")

    messages = [{'role': 'system', 'content': system_prompt}] + history

    try:
        console.print("[yellow]Alien Recon is analyzing signals...[/yellow]", end="\r")
        response = client.chat.completions.create(
            # Use a known, capable model. gpt-4o-mini is cost-effective.
            # Ensure this model supports tool calling.
            model="gpt-4o-mini",
            messages=messages,
            tools=tools,          # Pass defined tools
            tool_choice="auto",   # Let OpenAI decide when to use tools
            temperature=0.7,
        )
        console.print(" " * 40, end="\r") # Clear the "analyzing" message
        # Return the whole message object which contains content and/or tool_calls
        return response.choices[0].message

    except openai.AuthenticationError as e:
        logging.error(f"OpenAI Authentication Error: {e}")
        console.print("[bold red]Authentication Error: Invalid OpenAI API Key or organization setup issue.[/bold red]")
        return None
    except openai.RateLimitError as e:
        logging.error(f"OpenAI Rate Limit Error: {e}")
        console.print("[bold red]Rate Limit Exceeded. Please check your OpenAI plan and usage or wait and try again.[/bold red]")
        return None
    except openai.APIConnectionError as e:
        logging.error(f"OpenAI Connection Error: {e}")
        console.print("[bold red]Network Error: Could not connect to OpenAI API. Check your internet connection.[/bold red]")
        return None
    except openai.NotFoundError as e:
        logging.error(f"OpenAI Model Not Found or Invalid Request Error: {e}")
        console.print(f"[bold red]Error: The specified model might be invalid or unavailable for Tool Calling. {e}[/bold red]")
        console.print("[bold yellow]Suggestion: Check model name ('gpt-4o-mini', 'gpt-4o', 'gpt-4-turbo') and API key permissions.[/bold yellow]")
        return None
    except openai.BadRequestError as e:
        # Often indicates issues with the request structure, history, or tool definitions
        logging.error(f"OpenAI Bad Request Error: {e}", exc_info=True)
        console.print(f"[bold red]An error occurred with the request to OpenAI (Bad Request): {e}[/bold red]")
        console.print("[bold yellow]Suggestion: Check tool definitions, message structure, and history validity.[/bold yellow]")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during LLM communication: {e}", exc_info=True)
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        return None


# --- Main Execution Loop (Refactored for Tool Calling) ---
if __name__ == "__main__":
    console.print(Markdown("# Alien Recon AI Assistant - Initializing..."))
    openai_client = initialize_openai_client()
    console.print(Markdown(f"**Alien Recon:** {AGENT_WELCOME_MESSAGE}"))
    console.print(f"Using default wordlist: {DEFAULT_WORDLIST}")
    console.print("\nType 'exit' or 'quit' to end the session.")
    console.print("-" * 50)

    # --- Initialize State ---
    chat_history = []
    current_target = None
    # NEW state: Stores the tool call the user needs to confirm
    pending_tool_call = None

    while True:
        try:
            user_input = "" # Initialize user_input for the loop

            # --- Step 1: Handle Pending Tool Confirmation ---
            if pending_tool_call:
                tool_name = pending_tool_call.function.name
                tool_args = json.loads(pending_tool_call.function.arguments)
                # Construct user-friendly prompt based on tool
                prompt_text = f"[bold yellow]Confirmation Required:[/bold yellow]\n"
                if tool_name == "propose_nmap_scan":
                    prompt_text += f"  Tool: Nmap\n  Target: {tool_args.get('target')}\n  Arguments: {tool_args.get('arguments')}\n"
                elif tool_name == "propose_gobuster_scan":
                    # Use default wordlist if LLM didn't provide one
                    wordlist_to_use = tool_args.get('wordlist') or DEFAULT_WORDLIST
                    prompt_text += f"  Tool: Gobuster\n  Target: {tool_args.get('target')}:{tool_args.get('port')}\n  Wordlist: {os.path.basename(wordlist_to_use)}\n"
                else:
                    prompt_text += f"  Tool: {tool_name}\n  Arguments: {tool_args}\n" # Generic fallback
                prompt_text += "Shall Alien Recon proceed? (yes/no): "

                confirmation = console.input(prompt_text).lower().strip()

                if confirmation in ["yes", "y", "ok", "proceed", "affirmative"]:
                    console.print(f"[green]Affirmative. Executing {tool_name}...[/green]")
                    tool_result_content = ""
                    tool_error = False

                    # --- Execute the Confirmed Tool ---
                    if tool_name == "propose_nmap_scan":
                        nmap_target = tool_args.get('target')
                        nmap_args = tool_args.get('arguments', '-sV -T4') # Default if missing
                        scan_obj, error_msg = execute_nmap_scan(nmap_target, nmap_args)
                        tool_result_content = format_nmap_results_for_llm(scan_obj, nmap_target, error_msg)
                        if error_msg: tool_error = True

                    elif tool_name == "propose_gobuster_scan":
                        gb_target = tool_args.get('target')
                        gb_port = tool_args.get('port')
                        # Use default wordlist if LLM didn't provide one, or if provided path is invalid
                        gb_wordlist = tool_args.get('wordlist')
                        if not gb_wordlist or not os.path.exists(gb_wordlist):
                            if gb_wordlist: # Log if LLM suggested a bad path
                                 logging.warning(f"LLM suggested non-existent wordlist '{gb_wordlist}', falling back to default.")
                            gb_wordlist = DEFAULT_WORDLIST # Fallback to configured default

                        scan_output, error_msg = execute_gobuster_scan(gb_target, gb_port, gb_wordlist)
                        # Pass target_url context for better summary in formatter
                        protocol = "https" if gb_port in [443, 8443] else "http"
                        target_url_ctx = f"{protocol}://{gb_target}:{gb_port}"
                        tool_result_content = format_gobuster_results_for_llm(scan_output, target_url_ctx, error_msg)
                        if error_msg: tool_error = True
                        
                    elif tool_name == "propose_nikto_scan":
                        nikto_target = tool_args.get('target')
                        nikto_port = tool_args.get('port')
                        nikto_args = tool_args.get('nikto_arguments', "") # Get optional args
                        scan_output, error_msg = execute_nikto_scan(nikto_target, nikto_port, nikto_args)
                        target_ctx = f"{nikto_target}:{nikto_port}"
                        tool_result_content = format_nikto_results_for_llm(scan_output, target_ctx, error_msg)
                        if error_msg: tool_error = True
                    # ---- END NIKTO ADDITION ----
                    
                    elif tool_name == "propose_smb_enum":
                        smb_target = tool_args.get('target')
                        smb_args = tool_args.get('enum_arguments', "-A") # Default to -A
                        # Execute returns parsed JSON data or None
                        smb_data, error_msg = execute_smb_enum(smb_target, smb_args)
                        tool_result_content = format_smb_enum_results(smb_data, smb_target, error_msg)
                        if error_msg: tool_error = True # Mark if any error occurred
                    # ---- END ENUM4LINUX-NG ADDITION ----

                    else:
                        # Handle other tools if added
                        tool_result_content = json.dumps({"status": "Error", "message": f"Tool '{tool_name}' execution not implemented yet."})
                        tool_error = True

                    # --- Add Tool Result to History ---
                    chat_history.append({ # Add the original tool call message from assistant
                         "role": "assistant",
                         "tool_calls": [pending_tool_call.model_dump()] # Use model_dump() for serialization if needed by older library versions
                    })
                    chat_history.append({ # Add the result for that tool call
                        "role": "tool",
                        "tool_call_id": pending_tool_call.id,
                        "name": tool_name,
                        "content": tool_result_content,
                    })
                    logging.info(f"Appended tool result for {tool_name} (ID: {pending_tool_call.id}) to history.")

                    # --- Clear Pending Call and Get LLM Analysis ---
                    pending_tool_call = None
                    ai_message = get_llm_response(openai_client, chat_history, AGENT_SYSTEM_PROMPT)

                elif confirmation in ["no", "n", "negative", "cancel", "stop"]:
                    console.print("[yellow]Understood. Aborting the proposed scan.[/yellow]")
                    # Inform the LLM the user declined
                    chat_history.append({ # Add the original tool call message from assistant
                         "role": "assistant",
                         "tool_calls": [pending_tool_call.model_dump()]
                    })
                    chat_history.append({
                        "role": "tool",
                        "tool_call_id": pending_tool_call.id,
                        "name": tool_name,
                        "content": json.dumps({"status": "Cancelled", "message": "User declined the proposed scan."}),
                    })
                    logging.info(f"Appended user cancellation for {tool_name} (ID: {pending_tool_call.id}) to history.")
                    # Clear pending call and get next LLM step
                    pending_tool_call = None
                    ai_message = get_llm_response(openai_client, chat_history, AGENT_SYSTEM_PROMPT)

                else:
                    console.print("[yellow]Unclear response. Please answer 'yes' or 'no'. Aborting scan proposal.[/yellow]")
                    # We didn't get clear confirmation, treat as 'no' for safety
                    # Inform the LLM the user declined (due to unclear input)
                    chat_history.append({ # Add the original tool call message from assistant
                         "role": "assistant",
                         "tool_calls": [pending_tool_call.model_dump()]
                    })
                    chat_history.append({
                        "role": "tool",
                        "tool_call_id": pending_tool_call.id,
                        "name": tool_name,
                        "content": json.dumps({"status": "Cancelled", "message": "User provided unclear confirmation."}),
                    })
                    logging.info(f"Appended unclear confirmation for {tool_name} (ID: {pending_tool_call.id}) to history.")
                    pending_tool_call = None # Clear the pending call
                    ai_message = get_llm_response(openai_client, chat_history, AGENT_SYSTEM_PROMPT) # Ask LLM what to do next

                # --- Process LLM response after handling confirmation ---
                if ai_message:
                    # Check if the *new* response also contains tool calls
                    if ai_message.tool_calls:
                        # Store the first new proposed tool call for the *next* loop iteration
                        pending_tool_call = ai_message.tool_calls[0]
                        logging.info(f"LLM proposed new tool call: {pending_tool_call.function.name}")
                        # The text content might just be "Okay, proposing scan..." or empty, print if exists
                        if ai_message.content:
                             console.print(Markdown(f"**Alien Recon:** {ai_message.content}"))
                             chat_history.append({"role": "assistant", "content": ai_message.content}) # Add text part to history
                        # The actual tool call itself isn't added to history until user confirms & tool runs
                    else:
                        # Normal text response
                        ai_response_text = ai_message.content
                        if ai_response_text:
                             console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                             chat_history.append({"role": "assistant", "content": ai_response_text})
                else:
                    console.print("[bold red]AI assistant did not provide a response after tool execution/cancellation.[/bold red]")
                continue # Skip normal input prompt for this iteration

            # --- Step 2: Get User Input if no pending confirmation ---
            user_input = console.input("[bold cyan]You:[/bold cyan] ")
            user_input_lower = user_input.lower().strip()

            # --- Step 3: Handle Exit ---
            if user_input_lower in ["exit", "quit"]:
                console.print("[bold magenta]Deactivating Alien Recon Assistant. Safe travels, Earthling.[/bold magenta]")
                break
            if not user_input_lower:
                continue

            # --- Step 4: Process User Input ---
            chat_history.append({'role': 'user', 'content': user_input})

            # --- Handle Target Setting ---
            extracted_target = None
            target_command = False
            if user_input_lower.startswith(("target ", "analyze ", "set target ")):
                parts = user_input.split(maxsplit=1); extracted_target = parts[1].strip() if len(parts) > 1 else ""
                target_command = True
            # Allow setting target by just typing IP/domain if none is set yet
            elif current_target is None and (re.match(r"^\d{1,3}(\.\d{1,3}){3}$", user_input_lower) or ('.' in user_input_lower and ' ' not in user_input_lower and '/' not in user_input_lower)):
                 extracted_target = user_input_lower
                 target_command = True # Treat direct input as target command if none set

            if target_command:
                if extracted_target and (re.match(r"^\d{1,3}(\.\d{1,3}){3}$", extracted_target) or '.' in extracted_target): # Basic validation
                    current_target = extracted_target
                    console.print(f"[bold blue]Target Coordinates Updated:[/bold blue] {current_target}")
                    # Let the LLM react to the new target (should propose Nmap via tool call)
                else:
                    console.print(f"[bold red]Invalid target format: '{extracted_target}'. Please provide a valid IP or domain.[/bold red]")
                    # Remove the invalid user message from history? Or let LLM see the error? Let LLM see it.
                    # continue # Skip LLM call if target was invalid? No, let LLM respond.
                    pass

            # --- Step 5: Get LLM Response (for target setting or general chat) ---
            ai_message = get_llm_response(openai_client, chat_history, AGENT_SYSTEM_PROMPT)

            # --- Step 6: Process LLM Response ---
            if ai_message:
                if ai_message.tool_calls:
                    # LLM wants to propose a tool. Store it for the next loop iteration.
                    pending_tool_call = ai_message.tool_calls[0]
                    logging.info(f"LLM proposed tool call: {pending_tool_call.function.name}")
                    # Print any text content that came along with the tool call proposal
                    if ai_message.content:
                         console.print(Markdown(f"**Alien Recon:** {ai_message.content}"))
                         # Add the text part to history, the tool call isn't added until confirmed+run
                         chat_history.append({"role": "assistant", "content": ai_message.content})

                elif ai_message.content:
                    # Normal text response
                    ai_response_text = ai_message.content
                    console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                    chat_history.append({"role": "assistant", "content": ai_response_text})
                # Handle case where message has neither content nor tool_calls? Unlikely.
                elif not ai_message.content and not ai_message.tool_calls:
                     logging.warning("LLM message received with no content or tool calls.")
                     console.print("[grey50](Alien Recon provided no actionable response)[/grey50]")


            else: # Handle case where get_llm_response returned None
                console.print("[bold red]AI assistant failed to respond. Please check connection or API key and try again.[/bold red]")
                # Optionally remove the last user message from history if the API call failed badly
                if chat_history and chat_history[-1]['role'] == 'user':
                    chat_history.pop()


        except KeyboardInterrupt:
            console.print("\n[bold magenta]Deactivation signal received (Ctrl+C). Shutting down.[/bold magenta]")
            break
        except Exception as e:
            logging.error(f"An error occurred in the main loop: {e}", exc_info=True)
            console.print(f"[bold red]An unexpected error occurred in the main loop: {e}[/bold red]")
            # Potentially try to recover or just exit
            break
