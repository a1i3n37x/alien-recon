#!/usr/bin/env python3

import argparse
import logging
import sys
import subprocess # For running external tools
import shutil # For checking if tools exist
import socket # For resolving domain to IP
import re # For simple parsing
from urllib.parse import urlparse # For handling URLs

# --- Dependency Checks & Imports ---
try:
    import nmap
except ImportError:
    print("[-] Error: python-nmap library not found. Please install it using 'pip install python-nmap'")
    sys.exit(1)

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[-] Warning: dnspython library not found. DNS enumeration features will be limited.")
    print("[-] Install using 'pip install dnspython'")
    dns = None # Flag that dnspython is unavailable

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt" # Adjust if your path differs
# Default wordlist path - Assumes SecLists is installed at /usr/share/seclists/
DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"


# --- Tool Path Checks ---
# Check paths at the start to fail early if tools are missing
# Store paths or boolean flags indicating availability
TOOL_PATHS = {
    "nmap": shutil.which("nmap"),
    "gobuster": shutil.which("gobuster"),
    "nikto": shutil.which("nikto"),
    "enum4linux": shutil.which("enum4linux")
}

if not TOOL_PATHS["nmap"]:
    logging.error("Nmap is not installed or not found in your system's PATH. Core functionality unavailable.")
    sys.exit(1)

# --- Helper Functions ---
def resolve_target(target):
    """Resolves hostname to IP address, returns IP. Returns None on failure."""
    try:
        ip_address = socket.gethostbyname(target)
        logging.info(f"Resolved {target} to {ip_address}")
        return ip_address
    except socket.gaierror:
        logging.error(f"Could not resolve hostname: {target}")
        return None

def check_tool(tool_name):
    """Checks if a tool is available."""
    if not TOOL_PATHS[tool_name]:
        logging.warning(f"{tool_name.capitalize()} not found in PATH. Skipping associated scans.")
        return False
    return True

def run_command(command_list):
    """Runs an external command and returns its stdout."""
    logging.info(f"Executing command: {' '.join(command_list)}")
    try:
        # Using capture_output=True, text=True for easier handling
        result = subprocess.run(command_list, capture_output=True, text=True, check=False, timeout=300) # 5 min timeout
        if result.returncode != 0:
            logging.warning(f"Command '{command_list[0]}' exited with status {result.returncode}")
            logging.debug(f"Stderr: {result.stderr.strip()}")
        return result.stdout
    except FileNotFoundError:
        logging.error(f"Command not found: {command_list[0]}. Ensure it's installed and in PATH.")
        return None
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {' '.join(command_list)}")
        return None
    except Exception as e:
        logging.error(f"Error running command {' '.join(command_list)}: {e}")
        return None

# --- Scanner Functions ---

def run_nmap_scan(target_ip, profile):
    """Runs Nmap scan based on selected profile."""
    if not check_tool("nmap"): return None

    nm = nmap.PortScanner()
    scan_args = {
        "standard": "-sV -T4", # Service Version, Faster
        "deep": "-sV -sC -p- -T4", # SV, Scripts, All Ports, Faster
        "ctf": "-sV -p- -T4", # SV, All ports, Faster (often scripts aren't needed initially in CTFs)
        "web": "-sV -p 80,443,8000,8080,8443 -T4" # Common web ports
    }
    arguments = scan_args.get(profile, "-sV -T4") # Default to standard

    logging.info(f"Initiating Nmap scan ({arguments}) on target: {target_ip}")
    try:
        nm.scan(hosts=target_ip, arguments=arguments)
        logging.info(f"Nmap scan completed for target: {target_ip}")
        return nm
    except nmap.PortScannerError as e:
        logging.error(f"Nmap scan error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during Nmap scan: {e}")
        return None

def run_gobuster(target_url, wordlist):
    """Runs Gobuster for directory/file bruteforcing."""
    if not check_tool("gobuster"): return None
    # This check handles cases where the default SecLists path is wrong OR a user-provided path is wrong
    if not wordlist or not shutil.os.path.exists(wordlist):
        logging.warning(f"Wordlist not found at {wordlist}. Make sure SecLists is installed at /usr/share/seclists/ or provide a valid path with -w. Skipping Gobuster.")
        return None

    # Basic statuses to report - add more if needed
    statuses = "200,204,301,302,307,403"
    # Original command causing the error:
    # command = [TOOL_PATHS["gobuster"], "dir", "-u", target_url, "-w", wordlist, "-t", "50", "-q", "-s", statuses, "--no-error"]

    # Corrected command: Add '-b ""' to disable default blacklist
    command = [
        TOOL_PATHS["gobuster"], "dir",
        "-u", target_url,
        "-w", wordlist,
        "-t", "50",          # Threads
        "-q",                # Quiet mode
        "-s", statuses,      # Status codes to include
        "-b", "",            # Disable default blacklist (fixes the error)
        "--no-error"         # Don't print errors related to DNS etc.
    ]
    return run_command(command)

def run_nikto(target_url):
    """Runs Nikto for web vulnerability scanning."""
    if not check_tool("nikto"): return None
    # Basic Nikto scan - no output formatting yet for simplicity
    command = [TOOL_PATHS["nikto"], "-h", target_url, "-Tuning", "x 6"] # Avoid noisy methods initially
    return run_command(command)

def run_enum4linux(target_ip):
    """Runs enum4linux for SMB enumeration."""
    if not check_tool("enum4linux"): return None
    # Run with -a for all simple checks
    command = [TOOL_PATHS["enum4linux"], "-a", target_ip]
    return run_command(command)

def run_dns_enum(target_domain):
    """Performs basic DNS enumeration using dnspython."""
    if not dns: # Check if dnspython is available
        logging.warning("dnspython library not loaded, skipping DNS enumeration.")
        return None

    results = {"domain": target_domain, "records": {}}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    resolver = dns.resolver.Resolver()
    # Consider adding common server IPs like 8.8.8.8 if default fails

    logging.info(f"Initiating basic DNS enumeration for {target_domain}")
    for rtype in record_types:
        try:
            answers = resolver.resolve(target_domain, rtype)
            results["records"][rtype] = [str(rdata) for rdata in answers]
            logging.info(f"Found {rtype} records: {results['records'][rtype]}")
        except dns.resolver.NoAnswer:
            logging.debug(f"No {rtype} records found for {target_domain}.")
        except dns.resolver.NXDOMAIN:
            logging.error(f"Domain not found: {target_domain}. Aborting DNS enum.")
            return None # Domain doesn't exist
        except dns.exception.Timeout:
            logging.warning(f"DNS query timed out for {rtype} record.")
        except Exception as e:
            logging.warning(f"Error querying {rtype} records: {e}")

    # Basic Subdomain Brute-forcing (Example - VERY basic)
    # For real brute-forcing, dnsrecon or sublist3r via subprocess might be better
    # common_subdomains = ["www", "mail", "ftp", "dev", "staging", "admin", "test"]
    # results["subdomains"] = []
    # for sub in common_subdomains:
    #    try:
    #        fqdn = f"{sub}.{target_domain}"
    #        resolver.resolve(fqdn, "A")
    #        results["subdomains"].append(fqdn)
    #        logging.info(f"Found potential subdomain: {fqdn}")
    #    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
    #        pass
    #    except Exception as e:
    #        logging.debug(f"Error checking subdomain {sub}: {e}")

    return results


# --- Parsing & Display Functions ---

def parse_nmap_results(scan_data):
    """Parses Nmap data and returns a structured dict. Now returns data instead of printing."""
    host_results = {}
    if not scan_data:
        return host_results

    for host in scan_data.all_hosts():
        host_data = {"state": scan_data[host].state(), "protocols": {}}
        if host_data["state"] != 'up':
            continue

        host_results[host] = host_data
        protocols = scan_data[host].all_protocols()
        for proto in protocols:
            host_data["protocols"][proto] = {}
            ports = scan_data[host][proto].keys()
            for port in ports:
                port_info = scan_data[host][proto][port]
                state = port_info.get('state', 'unknown')
                service = port_info.get('name', '')
                version = port_info.get('version', '')
                product = port_info.get('product', '')
                full_version = f"{product} {version}".strip()
                host_data["protocols"][proto][port] = {
                    "state": state,
                    "service": service,
                    "version": full_version
                }
    return host_results

def parse_gobuster_output(output):
    """Simple parser for Gobuster output."""
    if not output: return []
    # Look for lines that don't start with '#' and likely contain URLs/paths
    # Example line: /images (Status: 301)
    # Example line: /index.html (Status: 200)
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
             # Extract path and status code more reliably if needed
             match = re.search(r"^(/[^ ]*)\s+\(Status:\s+(\d+)\)", line)
             if match:
                 path = match.group(1)
                 status = match.group(2)
                 findings.append({"path": path, "status": status})
             elif "(Status:" in line: # Catch lines that might not match regex perfectly
                 findings.append({"raw": line})
    return findings


def display_results(all_results):
    """Displays all collected results."""
    print("\n" + "="*40)
    print("~~~ Alien Recon: Consolidated Signal Analysis ~~~")
    print("="*40)

    for host, data in all_results.items():
        print(f"\n--- Analysis for Host: {host} ---")

        # Display Nmap Results
        if "nmap" in data:
            nmap_data = data["nmap"]
            print(f"  State: {nmap_data.get('state', 'unknown')}")
            if nmap_data.get('state') == 'up':
                for proto, ports in nmap_data.get('protocols', {}).items():
                    print(f"\n  Nmap - Protocol: {proto.upper()}")
                    if not ports:
                        print("    No open ports found for this protocol.")
                        continue
                    sorted_ports = sorted(ports.keys())
                    for port in sorted_ports:
                        p_info = ports[port]
                        print(f"    Port: {port:<6} State: {p_info.get('state',''):<8} Service: {p_info.get('service',''):<15} Version: {p_info.get('version','')}")
            else:
                 print("  Host reported as down by Nmap.")

        # Display DNS Results (if applicable)
        if "dns" in data:
            dns_data = data["dns"]
            print("\n  DNS Enumeration:")
            if dns_data and dns_data.get("records"):
                 for rtype, rdatas in dns_data["records"].items():
                      print(f"    {rtype}: {', '.join(rdatas)}")
            # if dns_data and dns_data.get("subdomains"):
            #    print(f"    Potential Subdomains Found: {', '.join(dns_data['subdomains'])}")
            elif not dns_data:
                 print("    DNS enumeration failed or yielded no results.")

        # Display Web Results
        if "web" in data:
             print("\n  Web Enumeration:")
             for port, web_data in data["web"].items():
                  print(f"    Port {port}:")
                  if "gobuster" in web_data and web_data["gobuster"]:
                       print(f"      Gobuster Findings:")
                       for finding in web_data["gobuster"]:
                           if "path" in finding:
                               print(f"        - Found Path: {finding['path']} (Status: {finding['status']})")
                           else:
                                print(f"        - {finding.get('raw', 'Unknown Finding')}")
                  elif "gobuster_error" in web_data:
                       print(f"      Gobuster Scan Error on port {port}.")

                  if "nikto" in web_data and web_data["nikto"]:
                       print(f"      Nikto Findings (Raw - requires manual review):")
                       # Print first few lines or summary - Nikto output is verbose
                       nikto_lines = web_data["nikto"].splitlines()
                       summary_lines = [line for line in nikto_lines if line.startswith('+') or "Target IP:" in line or "Target Hostname:" in line or "Target Port:" in line][:15] # Show key lines
                       for line in summary_lines:
                            print(f"        {line.strip()}")
                       if len(nikto_lines) > len(summary_lines): print("        [... Nikto output truncated ...]")
                  elif "nikto_error" in web_data:
                       print(f"      Nikto Scan Error on port {port}.")


        # Display SMB Results
        if "smb" in data:
            print("\n  SMB Enumeration (enum4linux - Raw Output):")
            if data["smb"]:
                # Print summary or key parts - enum4linux is very verbose
                smb_lines = data["smb"].splitlines()
                # Look for key sections (customize as needed)
                key_sections = ["[+] Getting OS Information", "[+] Enumerating Users", "[+] Getting domain SID", "[+] Enumerating printer info", "[+] Enumerating shares", "[+] Getting Share Enumeration"]
                summary_smb = []
                capture = False
                for line in smb_lines:
                    stripped_line = line.strip()
                    if any(section in stripped_line for section in key_sections):
                        capture = True
                        summary_smb.append(f"\n    {stripped_line}\n    " + "-"*len(stripped_line))
                    elif capture and stripped_line:
                         # Limit lines per section or total lines if needed
                         if len(summary_smb) < 50: # Limit total output lines
                              summary_smb.append(f"      {stripped_line}")
                         elif not summary_smb[-1].endswith("[...]"):
                              summary_smb.append("        [...]")

                print('\n'.join(summary_smb))

            else:
                print("    enum4linux scan failed or yielded no results.")

    print("\n" + "="*40)
    print("~~~ Alien Recon: Analysis Complete ~~~")
    print("="*40)


# --- Main Execution ---

if __name__ == "__main__":
    print("~~~ Alien Recon - Phase 1: Enhanced Reconnaissance Systems Online ~~~")

    parser = argparse.ArgumentParser(description="Alien Recon - Enhanced Scanner (Phase 1)")
    parser.add_argument("target", help="The target IP address or hostname.")
    parser.add_argument("-p", "--profile", choices=["standard", "deep", "ctf", "web"], default="standard",
                        help="Scan profile to use (default: standard).")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST,
                        help=f"Wordlist for Gobuster (default: {DEFAULT_WORDLIST}).")
    # Add --custom-nmap-args later if needed

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # --- Identify Target Type and Resolve ---
    target = args.target
    target_ip = None
    is_domain = False

    # Simple check if it looks like an IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        target_ip = target
    else:
        # Assume domain name
        is_domain = True
        target_ip = resolve_target(target)
        if not target_ip:
            logging.error(f"Cannot proceed without resolving {target} to an IP address.")
            sys.exit(1)

    # --- Master Results Dictionary ---
    # Stores results keyed by host IP
    master_results = {target_ip: {}}

    # --- Execute Workflow Based on Profile ---
    logging.info(f"Starting '{args.profile}' profile scan for {target} ({target_ip})")

    # 1. Nmap Scan (All profiles run Nmap)
    nmap_scan_data = run_nmap_scan(target_ip, args.profile)
    if nmap_scan_data:
        parsed_nmap = parse_nmap_results(nmap_scan_data)
        if target_ip in parsed_nmap: # Ensure host was 'up'
             master_results[target_ip]["nmap"] = parsed_nmap[target_ip]
             # Identify potential web ports from Nmap results for targeted scans
             web_ports = []
             if 'tcp' in master_results[target_ip]["nmap"].get("protocols", {}):
                  for port, p_info in master_results[target_ip]["nmap"]["protocols"]['tcp'].items():
                       # Check service name or common web ports
                       if p_info.get("state") == "open" and ("http" in p_info.get("service", "") or port in [80, 443, 8000, 8080, 8443]):
                            web_ports.append(port)
             logging.info(f"Identified potential web ports: {web_ports}")

             # Identify potential SMB ports
             smb_ports = []
             if 'tcp' in master_results[target_ip]["nmap"].get("protocols", {}):
                 for port, p_info in master_results[target_ip]["nmap"]["protocols"]['tcp'].items():
                      if p_info.get("state") == "open" and port in [139, 445]:
                           smb_ports.append(port)
             logging.info(f"Identified potential SMB ports: {smb_ports}")

        else:
             logging.warning(f"Nmap scan did not find host {target_ip} as 'up'.")
             # Display basic Nmap info anyway if desired
             master_results[target_ip]["nmap"] = {"state": "down or filtered"}

    else:
        logging.error("Nmap scan failed. Limited information available.")
        master_results[target_ip]["nmap"] = {"state": "scan_error"}
        web_ports = [] # Can't determine web ports
        smb_ports = [] # Can't determine SMB ports


    # 2. DNS Enum (Run if target was a domain, regardless of profile for now)
    if is_domain:
        master_results[target_ip]["dns"] = run_dns_enum(target)


    # 3. Web Enum (Run for 'web', 'deep', 'ctf' profiles if web ports found)
    if args.profile in ["web", "deep", "ctf"] and web_ports:
        master_results[target_ip]["web"] = {}
        for port in web_ports:
            protocol = "https" if port in [443, 8443] else "http" # Basic assumption
            base_url = f"{protocol}://{target_ip}:{port}"
            # Adjust URL if original target was domain name? Maybe use domain name here for Nikto/Gobuster if resolved?
            # Using IP for now to avoid certificate issues / SNI complexities easily.
            web_port_results = {}

            # Run Gobuster
            gobuster_output = run_gobuster(base_url, args.wordlist)
            if gobuster_output is not None:
                web_port_results["gobuster"] = parse_gobuster_output(gobuster_output)
            else:
                 web_port_results["gobuster_error"] = True

            # Run Nikto
            nikto_output = run_nikto(base_url)
            if nikto_output is not None:
                web_port_results["nikto"] = nikto_output # Store raw Nikto output for now
            else:
                 web_port_results["nikto_error"] = True

            master_results[target_ip]["web"][port] = web_port_results


    # 4. SMB Enum (Run for 'deep', 'ctf' profiles if SMB ports found)
    if args.profile in ["deep", "ctf"] and smb_ports:
        enum_output = run_enum4linux(target_ip)
        master_results[target_ip]["smb"] = enum_output # Store raw output


    # --- Display Final Results ---
    display_results(master_results)

    print("\n~~~ Alien Recon - Enhanced Reconnaissance Operations Concluded ~~~")
