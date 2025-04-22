#!/usr/bin/env python3

import os
import logging
import sys
import json # For formatting results for LLM
import re # For parsing target input
import subprocess # For running external tools
import shutil # For checking tool paths
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

# Default wordlist - ensure SecLists is installed here or user provides path later
DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"

# --- Agent Persona & Welcome ---
AGENT_SYSTEM_PROMPT = """
You are Alien Recon, a helpful AI assistant from Alien37.com.
You are guiding an Earthling specimen ('the user') through ethical hacking and cybersecurity concepts, analysis, and procedures, with a primary focus on **Capture The Flag (CTF) challenges for beginners.**
Your primary directive is to assist ONLY with ethical hacking tasks for which the user has explicit permission (like CTF platforms). **After the initial welcome message emphasizing ethics, assume subsequent user inputs providing targets (IPs/domains) fall within the authorized scope of the CTF simulation.** Do not repeatedly ask for permission confirmation unless the user's request seems explicitly outside standard CTF boundaries.
Speak in a knowledgeable, slightly detached but encouraging and guiding tone, characteristic of an advanced alien intelligence teaching a novice.
Use space, exploration, and alien metaphors where appropriate (e.g., 'probe' for scan, 'signals' for results, 'digital cosmos' for networks, 'coordinates' for targets).
Your goal is to help the user understand reconnaissance, scanning, vulnerability analysis, and potential exploitation paths within recognized frameworks (like CEH methodology phases or MITRE ATT&CK). Start simply and introduce frameworks as relevant data emerges. Focus guidance initially on typical CTF workflows and beginner steps.
Be conversational, but also **concise and directive when guiding the next step**. Explain *why* a step is taken briefly.
Do not perform any actions yourself, only provide analysis and guidance based on information provided by the user or previous context. **HOWEVER, when you suggest a specific scan (like Nmap, Gobuster) and the user confirms, you SHOULD process this confirmation by triggering the appropriate scan function and then presenting the summarized results back to the user and asking for analysis/next steps based on those *specific* results.**
Remember your limitations as an AI and always defer to the user for final decisions and actions.

**Workflow Instructions & Confirmation Phrasing:**

* **Initial Target:** When the user provides target coordinates, acknowledge them, suggest an initial Nmap scan (`nmap -sV [TARGET]`), explain its purpose concisely, and ask for confirmation using phrasing like: `"Shall I proceed with this Nmap scan on [TARGET]?"`
* **Nmap Analysis:** After Nmap results are provided, analyze them. If web ports (e.g., 80, 443, 8080) are found, identify them.
* **Suggesting Gobuster:** For *each* interesting web port found by Nmap, propose running Gobuster. Show the specific command (e.g., `gobuster dir -u http://[TARGET]:[PORT] -w [WORDLIST]`). Ask for confirmation for *that specific scan* using phrasing like: `"Shall we probe port [PORT_NUMBER] with Gobuster?"` or `"Confirm to proceed with Gobuster on port [PORT_NUMBER]?"`. **The question MUST contain the tool name ('Gobuster' or 'directory scan') AND the specific port number.**
* **Handling Scan Failures:** If a scan fails (like a timeout), report the failure to the user and ask how they want to proceed (e.g., different parameters, different tool, skip).
* **Suggesting Adjusted Scans:** If the user asks to adjust parameters (like wordlist) for a previously failed scan, state the *new* proposed command clearly. Then ask for confirmation using specific phrasing like: `"Shall I execute the Gobuster scan on port [PORT_NUMBER] with the adjusted parameters?"` or `"Proceed with the adjusted Gobuster probe on port [PORT_NUMBER]?"`. **The confirmation question MUST reiterate the tool (Gobuster) and the specific port number.**
* **Gobuster Analysis:** After Gobuster results are provided, analyze them in context with Nmap findings. Suggest next steps (investigate specific paths, try Nikto on the same port, try Gobuster on other ports) and ask for confirmation for the *next specific action*, clearly stating the action and target (e.g., "Shall we investigate the `/admin` path further?", "Shall I run Nikto on port [PORT_NUMBER]?").

**General:** Be directive about the *next logical step* based on findings. Always ask for confirmation before suggesting the script should execute a tool. Ensure confirmation questions are specific about the tool and target details (like port number).
"""
AGENT_WELCOME_MESSAGE = """
Greetings, CTF Participant. Alien Recon online. I detect you are preparing to engage a Capture The Flag simulation construct. Excellent choice for honing your skills.

My designation is AI Assistant from Alien37, and my function is to guide your analysis through this challenge. Think of me as mission control, providing tactical suggestions based on incoming signals.

To initiate our reconnaissance protocols, I require the **primary coordinates** for your designated target. Please provide the **IP address or domain name** of the CTF challenge system you are authorized to investigate.

You can designate the target using a command structure like:
* `target 10.10.14.2`
* `analyze ctfbox.local`
* `set target 192.168.30.125`

Once the target coordinates are locked, we can begin the standard CTF procedure, likely involving initial network probes (scanning).

**Reminder:** Operate strictly within the boundaries defined by the CTF organizers. Ethical conduct is paramount, even in simulations.

Awaiting target designation... What are the coordinates?
"""

# --- Tool Path Checks ---
TOOL_PATHS = {
    "nmap": shutil.which("nmap"),
    "gobuster": shutil.which("gobuster"),
}

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
        result = subprocess.run(command_list, capture_output=True, text=True, check=False, timeout=600) # 10 min timeout
        if result.returncode != 0:
            logging.warning(f"Command '{command_list[0]}' exited with status {result.returncode}. Stderr: {result.stderr.strip()}")
        return result.stdout
    except FileNotFoundError:
        logging.error(f"Command not found: {command_list[0]}. Ensure it's installed and in PATH.")
        console.print(f"[bold red]Error: Command '{command_list[0]}' not found. Is it installed and in your PATH?[/bold red]")
        return None
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {' '.join(command_list)}")
        console.print(f"[bold red]Error: Command {' '.join(command_list)} timed out.[/bold red]")
        return None
    except Exception as e:
        logging.error(f"Error running command {' '.join(command_list)}: {e}")
        console.print(f"[bold red]Error running command {' '.join(command_list)}: {e}[/bold red]")
        return None

# --- Core Functions ---
def initialize_openai_client():
    if not API_KEY:
        console.print("[bold red]Error: OPENAI_API_KEY not found in .env file or environment variables.[/bold red]")
        sys.exit(1)
    try:
        client = openai.OpenAI(api_key=API_KEY)
        console.print("[green]OpenAI client initialized successfully.[/green]")
        return client
    except Exception as e:
        logging.error(f"Failed to initialize OpenAI client: {e}", exc_info=True)
        console.print(f"[bold red]Error initializing OpenAI client: {e}[/bold red]")
        sys.exit(1)

# --- Nmap Execution and Formatting ---
def execute_nmap_scan(target_ip, arguments="-sV -T4"):
    if not nmap:
        console.print("[bold red]Error: Nmap scan function called, but python-nmap library is not available.[/bold red]")
        return None
    if not check_tool("nmap"): return None

    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        console.print("[bold red]Error: Nmap program was not found in path. Ensure Nmap is installed system-wide.[/bold red]")
        return None
    except Exception as e:
        console.print(f"[bold red]Error initializing Nmap PortScanner: {e}[/bold red]")
        return None

    console.print(f"[yellow]Initiating Nmap probe ({arguments}) on {target_ip}...[/yellow]")
    spinner = Spinner("dots", text=" Scanning...")
    try:
        with console.status(spinner):
             nm.scan(hosts=target_ip, arguments=arguments, sudo=False)
        console.print(f"[green]Nmap probe complete for {target_ip}.[/green]")
        return nm
    except nmap.PortScannerError as e:
        console.print(f"[bold red]Nmap scan error: {e}[/bold red]")
        return None
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred during Nmap scan: {e}[/bold red]")
        return None

def format_nmap_results_for_llm(scan_data, target_ip):
    if not scan_data or not scan_data.all_hosts():
        return json.dumps({"scan_summary": f"Nmap scan on {target_ip} yielded no results or host was down.", "hosts": []})

    results = {"scan_summary": f"Nmap scan results for {target_ip}:", "hosts": []}
    for host in scan_data.all_hosts():
        host_info = {"host": host, "status": scan_data[host].state(), "open_ports": []}
        if host_info["status"] == 'up':
            for proto in scan_data[host].all_protocols():
                ports = scan_data[host][proto].keys()
                for port in sorted(ports):
                    port_info = scan_data[host][proto][port]
                    state = port_info.get('state', 'unknown')
                    if state == 'open':
                        service = port_info.get('name', '')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')
                        full_version = f"{product} {version}".strip()
                        host_info["open_ports"].append({
                            "port": port, "protocol": proto,
                            "service": service, "version": full_version
                        })
        results["hosts"].append(host_info)
    return json.dumps(results, indent=2)

# --- Gobuster Execution and Formatting ---
def execute_gobuster_scan(target_ip, port, wordlist=DEFAULT_WORDLIST):
    if not check_tool("gobuster"): return None
    if not wordlist or not os.path.exists(wordlist):
        console.print(f"[bold orange_red1]Warning: Wordlist not found at '{wordlist}'. Skipping Gobuster.[/bold orange_red1]")
        return None

    protocol = "https" if port in [443, 8443] else "http"
    target_url = f"{protocol}://{target_ip}:{port}"
    statuses = "200,204,301,302,307,403"
    command = [
        TOOL_PATHS["gobuster"], "dir", "-u", target_url, "-w", wordlist,
        "-t", "50", "-q", "-s", statuses, "-b", "", "--no-error"
    ]

    console.print(f"[yellow]Initiating Gobuster probe ({os.path.basename(wordlist)}) on {target_url}...[/yellow]")
    spinner = Spinner("dots", text=" Scanning...")
    output = None
    try:
        with console.status(spinner):
            output = run_command(command)
        console.print(f"[green]Gobuster probe complete for {target_url}.[/green]")
        return output
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred during Gobuster execution setup: {e}[/bold red]")
        return None

def format_gobuster_results_for_llm(output, target_url_context):
    if output is None:
         return json.dumps({"scan_summary": f"Gobuster scan related to {target_url_context} failed or was skipped.", "findings": []})

    findings = []
    count = 0
    limit = 50
    truncated = False
    raw_url_base = target_url_context
    match_base = re.match(r"(https?://[^/]+)", target_url_context)
    if match_base: raw_url_base = match_base.group(1)

    output_lines = output.splitlines()
    for line in output_lines:
        line = line.strip()
        if not line or line.startswith("#"): continue
        if count >= limit:
            truncated = True
            break

        match = re.search(r"^(/.*?)\s+\(Status:\s*(\d+)\)", line)
        if match:
            path = match.group(1)
            status = match.group(2)
            full_url = f"{raw_url_base.rstrip('/')}{path}" if raw_url_base else path
            findings.append({"url/path": full_url, "status": status})
            count += 1
        elif "(Status:" in line:
            findings.append({"raw": line})
            count += 1

    summary = f"Gobuster scan related to {target_url_context} completed. Found {len(findings)} potential paths/files."
    if truncated: summary += f" (Showing first {limit})"
    if not findings and output is not None and len(output.strip()) > 0:
         summary += " (Output received but no standard findings parsed)."
    elif not findings:
         summary += " (No findings)."

    return json.dumps({"scan_summary": summary, "findings": findings }, indent=2)

# --- LLM Interaction ---
def get_llm_response(client, user_prompt, system_prompt, history):
    # Ensure history doesn't grow indefinitely (simple turn limit)
    MAX_HISTORY_TURNS = 15
    if len(history) > MAX_HISTORY_TURNS * 2:
        history = history[-(MAX_HISTORY_TURNS * 2):]
        logging.info(f"Chat history truncated to last {MAX_HISTORY_TURNS} turns.")

    messages = [{'role': 'system', 'content': system_prompt}] + history + [{'role': 'user', 'content': user_prompt}]
    try:
        console.print("[yellow]Alien Recon is analyzing signals...[/yellow]", end="\r")
        response = client.chat.completions.create(
            model="gpt-4.1-nano", # User-specified model
            messages=messages,
            temperature=0.7,
        )
        console.print(" " * 40, end="\r")
        ai_response = response.choices[0].message.content
        return ai_response.strip()
    # (Error handling as before)
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
        console.print(f"[bold red]Error: The specified model ('gpt-4.1-nano') might be invalid or unavailable. {e}[/bold red]")
        console.print("[bold yellow]Suggestion: Try models like 'gpt-4o-mini', 'gpt-4o', or 'gpt-4-turbo'.[/bold yellow]")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during LLM communication: {e}", exc_info=True)
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        return None


# --- Main Execution Loop (Explicit State Logic) ---
if __name__ == "__main__":
    console.print(Markdown("# Alien Recon AI Assistant - Initializing..."))
    openai_client = initialize_openai_client()
    console.print(Markdown(f"**Alien Recon:** {AGENT_WELCOME_MESSAGE}"))
    console.print("\nType 'exit' or 'quit' to end the session.")
    console.print("-" * 50)

    # --- Initialize State ---
    chat_history = []
    current_target = None
    waiting_for_confirmation = None
    suggested_scan_args = "-sV -T4"

    while True:
        try:
            # --- Get User Input ---
            user_input = console.input("[bold cyan]You:[/bold cyan] ")
            user_input_lower = user_input.lower()
            user_input_strip = user_input.strip()

            # --- Handle Exit ---
            if user_input_lower in ["exit", "quit"]:
                console.print("[bold magenta]Deactivating Alien Recon Assistant. Safe travels, Earthling.[/bold magenta]")
                break
            if not user_input_strip:
                continue

            # --- Process Input based on State ---
            ai_response_text = None # Reset response text
            next_confirmation_state = None # Reset next state decision

            # --- BRANCH 1: Handle User Confirmation ---
            if waiting_for_confirmation is not None:
                # print(f"DEBUG: State Check: waiting_for_confirmation = {waiting_for_confirmation}") # Optional Debug
                is_affirmative = user_input_strip.lower() in ["yes", "y", "ok", "proceed", "affirmative", "yes please", "run the scan", "initiate probe", "do it", "sure"]
                current_confirmation_action = waiting_for_confirmation # Store action
                waiting_for_confirmation = None # Reset state immediately upon receiving response
                # print(f"DEBUG: Is affirmative? {is_affirmative}. Reset waiting_for_confirmation.") # Optional Debug

                if is_affirmative:
                    # print(f"DEBUG: Affirmative confirmation received for {current_confirmation_action}") # Optional Debug

                    # --- Handle Nmap ---
                    if current_confirmation_action == "nmap_scan":
                        console.print("[green]Affirmative. Initiating Nmap probe...[/green]") # Script message
                        if current_target:
                            scan_results_obj = execute_nmap_scan(current_target, suggested_scan_args)
                            if scan_results_obj:
                                formatted_results = format_nmap_results_for_llm(scan_results_obj, current_target)
                                console.print(f"[blue]Nmap scan complete.[/blue]") # Script message
                                analysis_prompt = (
                                    f"Nmap scan ({suggested_scan_args}) on {current_target} complete.\n"
                                    f"Results:\n```json\n{formatted_results}\n```\n"
                                    f"Analyze results. Propose next step (likely Gobuster on HTTP ports found) & ask confirmation."
                                )
                                # print("DEBUG: Calling LLM for Nmap analysis...") # Optional Debug
                                ai_response_text = get_llm_response(openai_client, analysis_prompt, AGENT_SYSTEM_PROMPT, chat_history)
                                # Update history & print response HERE
                                if ai_response_text:
                                     chat_history.append({'role': 'user', 'content': analysis_prompt}) # History gets prompt
                                     chat_history.append({'role': 'assistant', 'content': ai_response_text})
                                     console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                                     # --- EXPLICITLY set state if LLM asks for Gobuster confirmation ---
                                     # Use the corrected logic: parse port from command example
                                     response_lower = ai_response_text.lower()
                                     response_ends_q = ai_response_text.strip().endswith("?")
                                     mentions_gobuster = "gobuster" in response_lower or "directory" in response_lower
                                     mentions_confirm_phrase = re.search(r"(shall|confirm|proceed|would you like|execute)", response_lower)

                                     # print(f"DEBUG (Post-Nmap): Mentions Gobuster? {mentions_gobuster}, Asks Question? {response_ends_q}, Mentions Confirm Phrase? {mentions_confirm_phrase is not None}") # Optional Debug

                                     if current_target and mentions_gobuster and response_ends_q and mentions_confirm_phrase:
                                         command_parse_regex = r"gobuster.*?-(?:u|url)\s+(?:https?://)?[\d\.]+?:(\d+)" # Look for :port in URL argument
                                         cmd_match = re.search(command_parse_regex, response_lower) # Search in the LLM response text
                                         # print(f"DEBUG: Command Parse Regex Match Object: {cmd_match}") # Optional Debug
                                         if cmd_match:
                                             port_num = int(cmd_match.group(1))
                                             next_confirmation_state = ("gobuster", port_num)
                                             print(f"DEBUG: STATE SET after Nmap analysis (parsed command): waiting_for_confirmation = {next_confirmation_state}") # Keep Debug
                                         else:
                                             # Fallback: Try parsing port near keywords if command parsing fails
                                             port_parse_regex = r"port\s+(\d+)"
                                             match = re.search(port_parse_regex, response_lower)
                                             if match:
                                                  next_confirmation_state = ("gobuster", int(match.group(1)))
                                                  print(f"DEBUG: STATE SET after Nmap analysis (parsed 'port XX'): waiting_for_confirmation = {next_confirmation_state}") # Keep Debug
                                                  logging.info(f"State set by script (fallback parse): waiting for Gobuster on port {match.group(1)}.")
                                             else:
                                                 logging.warning("LLM suggested Gobuster but failed to parse port from command example or text.")
                                                 print("DEBUG: STATE NOT SET: Gobuster suggested but failed to parse port.") # Keep Debug
                                     # else: print("DEBUG: STATE NOT SET: Gobuster confirm pattern not fully matched.") # Optional Debug

                                else: # LLM analysis failed
                                     console.print("[bold red]Agent failed to provide analysis for Nmap results.[/bold red]")
                            else: # Nmap scan failed
                                console.print(f"[bold red]Nmap scan failed for {current_target}.[/bold red]")
                                ai_response_text = get_llm_response(openai_client, f"Nmap scan on {current_target} failed. Inform user.", AGENT_SYSTEM_PROMPT, chat_history)
                                if ai_response_text: # Print failure message from LLM
                                     chat_history.append({'role': 'user', 'content': user_input}) # User's 'yes'
                                     chat_history.append({'role': 'assistant', 'content': ai_response_text})
                                     console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                        else: # Target lost safeguard
                            console.print("[bold red]Error: Nmap confirmed but target lost.[/bold red]")
                            ai_response_text = get_llm_response(openai_client, "Nmap confirmed but target lost. Ask user.", AGENT_SYSTEM_PROMPT, chat_history)
                            if ai_response_text:
                                 chat_history.append({'role': 'user', 'content': user_input})
                                 chat_history.append({'role': 'assistant', 'content': ai_response_text})
                                 console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))

                    # --- Handle Gobuster ---
                    elif isinstance(current_confirmation_action, tuple) and current_confirmation_action[0] == "gobuster":
                        port_to_scan = current_confirmation_action[1]
                        console.print(f"[green]Affirmative. Initiating Gobuster probe on port {port_to_scan}...[/green]") # Script message
                        if current_target and port_to_scan:
                            # --- Execute Scan ---
                            # print(f"DEBUG: === Calling execute_gobuster_scan(target={current_target}, port={port_to_scan}, wordlist={DEFAULT_WORDLIST}) ===") # Optional Debug
                            gobuster_output = execute_gobuster_scan(current_target, port_to_scan, DEFAULT_WORDLIST)
                            # print(f"DEBUG: === execute_gobuster_scan returned Type: {type(gobuster_output)} ===") # Optional Debug
                            # if isinstance(gobuster_output, str): print(f"DEBUG: Gobuster Output (first 200 chars):\n'''{gobuster_output[:200]}...'''\n" + "-"*20) # Optional Debug
                            # elif gobuster_output is None: print("DEBUG: Gobuster Output: None (Execution likely failed)") # Optional Debug

                            # --- Format Results ---
                            if gobuster_output is not None: # Check if execution likely succeeded
                                # print("DEBUG: Calling format_gobuster_results_for_llm") # Optional Debug
                                formatted_results = format_gobuster_results_for_llm(gobuster_output, f"{current_target}:{port_to_scan}")
                                # print(f"DEBUG: Formatted Gobuster JSON for LLM:\n{formatted_results}") # Optional Debug
                                console.print(f"[blue]Gobuster scan on port {port_to_scan} complete.[/blue]") # Script message

                                # --- Create Analysis Prompt ---
                                analysis_prompt = (
                                    f"Gobuster scan on {current_target}:{port_to_scan} complete.\n"
                                    f"Results:\n```json\n{formatted_results}\n```\n"
                                    f"Analyze findings. Combine context. Suggest next steps & ask confirmation."
                                )
                                # print(f"DEBUG: Analysis Prompt for LLM (Gobuster):\n{analysis_prompt}\n--------------------") # Optional Debug

                                # --- Call LLM for Analysis ---
                                ai_response_text = get_llm_response(openai_client, analysis_prompt, AGENT_SYSTEM_PROMPT, chat_history)
                                # print(f"DEBUG: LLM Analysis call returned (Gobuster). Response: {ai_response_text is not None}") # Optional Debug
                                # Update history & print response
                                if ai_response_text:
                                     chat_history.append({'role': 'user', 'content': analysis_prompt}) # History gets prompt
                                     chat_history.append({'role': 'assistant', 'content': ai_response_text})
                                     console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                                     # --- Explicitly set state for next tool if suggested ---
                                     # Example: if "nikto" in ai_response_text.lower() ... set state ...
                                else: # LLM analysis failed
                                     console.print("[bold red]Agent failed to provide analysis for Gobuster results.[/bold red]")
                            else: # Gobuster execution failed (returned None)
                                # print(f"DEBUG: Gobuster scan execution failed path taken.") # Optional Debug
                                console.print(f"[bold red]Gobuster scan failed for {current_target}:{port_to_scan}.[/bold red]")
                                # Ask LLM how to proceed after failure
                                ai_response_text = get_llm_response(openai_client, f"Gobuster scan on {current_target}:{port_to_scan} failed. Inform user.", AGENT_SYSTEM_PROMPT, chat_history)
                                if ai_response_text:
                                     chat_history.append({'role': 'user', 'content': user_input}) # User's 'yes'
                                     chat_history.append({'role': 'assistant', 'content': ai_response_text})
                                     console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                        else: # Safeguard: Target or Port lost
                             # print(f"DEBUG: Gobuster confirmation but target/port is None ({current_target=}, {port_to_scan=}).") # Optional Debug
                             console.print(f"[bold red]Critical Error: Gobuster scan confirmed but target/port unknown.[/bold red]")
                             ai_response_text = get_llm_response(openai_client, f"Gobuster confirmed for port {port_to_scan} but target/port lost. Ask user.", AGENT_SYSTEM_PROMPT, chat_history)
                             if ai_response_text:
                                  chat_history.append({'role': 'user', 'content': user_input})
                                  chat_history.append({'role': 'assistant', 'content': ai_response_text})
                                  console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))

                    # --- Handle Other Tool Confirmations Here ---
                    else:
                        # print(f"DEBUG: Unrecognized confirmation state: {current_confirmation_action}") # Optional Debug
                        console.print("[bold yellow]Affirmative response, but expected action unclear. Asking LLM.[/bold yellow]")
                        ai_response_text = get_llm_response(openai_client, user_input, AGENT_SYSTEM_PROMPT, chat_history)
                        if ai_response_text: # Print LLM response
                             chat_history.append({'role': 'user', 'content': user_input})
                             chat_history.append({'role': 'assistant', 'content': ai_response_text})
                             console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                             # Check if this asks for confirmation (less critical fallback)
                             if current_target and re.search(r"nmap.*?shall.*?proceed", ai_response_text.lower()): next_confirmation_state = "nmap_scan"
                             elif current_target and re.search(r"gobuster.*?port\s+(\d+).*?shall.*?proceed", ai_response_text.lower()):
                                  match = re.search(r"port\s+(\d+)", ai_response_text.lower()); next_confirmation_state = ("gobuster", int(match.group(1))) if match else None

                else: # User response was NOT affirmative
                    # print("DEBUG: Confirmation bypassed by user input.") # Optional Debug
                    console.print("[yellow]Confirmation bypassed. Processing input normally.[/yellow]")
                    # Process original non-affirmative input normally
                    ai_response_text = get_llm_response(openai_client, user_input, AGENT_SYSTEM_PROMPT, chat_history)
                    if ai_response_text:
                         chat_history.append({'role': 'user', 'content': user_input})
                         chat_history.append({'role': 'assistant', 'content': ai_response_text})
                         console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                         # Check if this response asks for confirmation (fallback)
                         if current_target and re.search(r"nmap.*?shall.*?proceed", ai_response_text.lower()): next_confirmation_state = "nmap_scan"
                         elif current_target and re.search(r"gobuster.*?port\s+(\d+).*?shall.*?proceed", ai_response_text.lower()):
                              match = re.search(r"port\s+(\d+)", ai_response_text.lower()); next_confirmation_state = ("gobuster", int(match.group(1))) if match else None

                # Update the global state variable for the *next* loop iteration
                waiting_for_confirmation = next_confirmation_state
                continue # Go to next loop iteration AFTER handling confirmation branch

            # --- BRANCH 2: Handle Target Input (if not handling confirmation) ---
            extracted_target = None # Reset
            if user_input_lower.startswith(("target ", "analyze ", "set target ")):
                # print("DEBUG: Input recognized as target command.") # Optional Debug
                parts = user_input.split(maxsplit=1); extracted_target = parts[1].strip() if len(parts) > 1 else ""
            elif current_target is None and (re.match(r"^\d{1,3}(\.\d{1,3}){3}$", user_input_strip) or ('.' in user_input_strip and ' ' not in user_input_strip)):
                 extracted_target = user_input_strip
                 # print(f"DEBUG: Direct input '{extracted_target}' recognized as potential target.") # Optional Debug

            if extracted_target is not None: # Check if extraction was attempted
                if extracted_target and (re.match(r"^\d{1,3}(\.\d{1,3}){3}$", extracted_target) or '.' in extracted_target): # Check if valid
                    current_target = extracted_target
                    console.print(f"[bold blue]Target Coordinates Updated:[/bold blue] {current_target}")
                    waiting_for_confirmation = None # Reset confirmation
                    # Ask LLM to respond (it should suggest Nmap)
                    ai_response_text = get_llm_response(openai_client, user_input, AGENT_SYSTEM_PROMPT, chat_history)
                    if ai_response_text:
                         chat_history.append({'role': 'user', 'content': user_input})
                         chat_history.append({'role': 'assistant', 'content': ai_response_text})
                         console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                         # --- EXPLICITLY SET NMAP CONFIRM STATE ---
                         response_ends_q = ai_response_text.strip().endswith("?")
                         mentions_nmap = "nmap" in ai_response_text.lower()
                         # print(f"DEBUG (Post-Target): Response mentions Nmap? {mentions_nmap}, Ends with '?'? {response_ends_q}") # Optional Debug
                         if mentions_nmap and response_ends_q and re.search(r"(shall|confirm|proceed|approve|run this scan)", ai_response_text.lower()):
                             waiting_for_confirmation = "nmap_scan"
                             # print(f"DEBUG: STATE SET after target: waiting_for_confirmation = {waiting_for_confirmation}") # Optional Debug
                         # else: print(f"DEBUG: STATE NOT SET after target: Nmap confirm pattern not found.") # Optional Debug
                else: # Invalid format or empty target command
                    ai_response_text = get_llm_response(openai_client, f"Input '{user_input}' not valid target. Ask for valid IP/domain.", AGENT_SYSTEM_PROMPT, chat_history)
                    if ai_response_text:
                        chat_history.append({'role': 'user', 'content': user_input})
                        chat_history.append({'role': 'assistant', 'content': ai_response_text})
                        console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                    waiting_for_confirmation = None # Reset state
                continue # Finish handling this turn

            # --- BRANCH 3: Normal Input Processing (if not confirmation and not target) ---
            else:
                # print("DEBUG: Processing input as normal conversation.") # Optional Debug
                ai_response_text = get_llm_response(openai_client, user_input, AGENT_SYSTEM_PROMPT, chat_history)
                if ai_response_text:
                     chat_history.append({'role': 'user', 'content': user_input})
                     chat_history.append({'role': 'assistant', 'content': ai_response_text})
                     console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                     # Check if this normal response asks for confirmation (fallback)
                     next_confirmation_state = None # Default
                     response_ends_q = ai_response_text.strip().endswith("?")
                     if current_target and response_ends_q:
                         response_lower = ai_response_text.lower()
                         nmap_confirm_check = "nmap" in response_lower and re.search(r"(shall|confirm|proceed|approve|run this scan)", response_lower)
                         gobuster_confirm_check = ("gobuster" in response_lower or "directory" in response_lower) and "port" in response_lower and re.search(r"(shall|confirm|proceed|would you like|run this|execute)", response_lower)

                         if nmap_confirm_check: next_confirmation_state = "nmap_scan"
                         elif gobuster_confirm_check:
                             port_parse_regex = r"port\s+(\d+)"
                             match = re.search(port_parse_regex, response_lower); next_confirmation_state = ("gobuster", int(match.group(1))) if match else None
                     waiting_for_confirmation = next_confirmation_state # Update state


        except KeyboardInterrupt:
            console.print("\n[bold magenta]Deactivation signal received (Ctrl+C). Shutting down.[/bold magenta]")
            break
        except Exception as e:
             logging.error(f"An error occurred in the main loop: {e}", exc_info=True)
             console.print(f"[bold red]An unexpected error occurred in the main loop: {e}[/bold red]")
