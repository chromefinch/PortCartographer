#!/usr/bin/env python3

import subprocess
import os
import re
import argparse
import shutil
from datetime import datetime

# --- Configuration ---
# Nmap
NMAP_NSE_SCRIPTS = "dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-recursion,dns-service-discovery,dns-srv-enum,fcrdns,ftp-anon,ftp-bounce,ftp-libopie,ftp-syst,ftp-vuln-cve2010-4221,http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-backup-finder,http-bigip-cookie,http-cakephp-version,http-config-backup,http-cookie-flags,http-devframework,http-exif-spider,http-favicon,http-frontpage-login,http-generator,http-git,http-headers,http-hp-ilo-info,http-iis-webdav-vuln,http-internal-ip-disclosure,http-jsonp-detection,http-mcmp,http-ntlm-info,http-passwd,http-php-version,http-qnap-nas-info,http-sap-netweaver-leak,http-security-headers,http-server-header,http-svn-info,http-trane-info,http-userdir-enum,http-vlcstreamer-ls,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-2129,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-cve2017-1001000,http-vuln-misfortune-cookie,http-webdav-scan,http-wordpress-enum,http-wordpress-users,https-redirect,imap-capabilities,imap-ntlm-info,ip-https-discover,membase-http-info,msrpc-enum,mysql-audit,mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables,mysql-vuln-cve2012-2122,nfs-ls,nfs-showmount,nfs-statfs,pop3-capabilities,pop3-ntlm-info,pptp-version,rdp-ntlm-info,rdp-vuln-ms12-020,realvnc-auth-bypass,riak-http-info,rmi-vuln-classloader,rpc-grind,rpcinfo,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-print-text,smb-protocols,smb-security-mode,smb-vuln-cve-2017-7494,smb-vuln-ms10-061,smb-vuln-ms17-010,smb2-capabilities,smb2-security-mode,smb2-vuln-uptime,smtp-commands,smtp-ntlm-info,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,ssh-auth-methods,sshv1,ssl-ccs-injection,ssl-cert,ssl-heartbleed,ssl-poodle,sslv2-drown,sslv2,telnet-encryption,telnet-ntlm-info,tftp-enum,unusual-port,vnc-info,vnc-title"
NMAP_TOP_UDP_PORTS = "100"
NMAP_QUICK_SCAN_PORTS_ARG = "-p-" # Default for the --nmap-ports argument and the prompt

# Nikto
NIKTO_MAXTIME = "3m"

# Feroxbuster (sensible defaults, assuming Seclists installation)
FEROXBUSTER_WORDLIST_LINUX = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
FEROXBUSTER_EXTENSIONS_LINUX = "php,html,txt,pdf,sh"
FEROXBUSTER_WORDLIST_WINDOWS = "/usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt"
FEROXBUSTER_EXTENSIONS_WINDOWS = "php,html,asp,aspx,jsp,pdf,wsdl"
FEROXBUSTER_WORDLIST_UNKNOWN = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" # Using medium for unknown
FEROXBUSTER_EXTENSIONS_UNKNOWN = "php,html,txt,asp,aspx,jsp,pdf,wsdl,asmx"
FEROXBUSTER_THREADS = "50" # Adjusted from 100 to be slightly less aggressive by default

# WhatWeb
WHATWEB_AGGRESSION = "3"

# WPScan
WPSCAN_API_TOKEN = "" # Add your wpscan.com API token here for full vulnerability data

# --- Color Definitions ---
class TermColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_info(msg): print(f"{TermColors.OKBLUE}[*] {msg}{TermColors.ENDC}")
def print_success(msg): print(f"{TermColors.OKGREEN}[+] {msg}{TermColors.ENDC}")
def print_warning(msg): print(f"{TermColors.WARNING}[!] {msg}{TermColors.ENDC}")
def print_error(msg): print(f"{TermColors.FAIL}[-] {msg}{TermColors.ENDC}")
def print_header(msg): print(f"{TermColors.HEADER}{TermColors.BOLD}{msg}{TermColors.ENDC}")

# --- Helper Functions ---
def run_command(command, output_file, cwd=None):
    """Runs a shell command and saves its output to a file."""
    try:
        print_info(f"Running: {' '.join(command)}")
        process = subprocess.run(command, capture_output=True, text=True, check=False, cwd=cwd)
        # For Nmap -oA, Nmap handles file creation. We still log stdout to the .txt file.
        # For other commands, output_file is the primary destination.
        with open(output_file, "w") as f:
            f.write(f"Command: {' '.join(command)}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write("--- STDOUT ---\n")
            f.write(process.stdout)
            f.write("\n--- STDERR ---\n")
            f.write(process.stderr)
        
        if process.returncode != 0:
            is_wpscan_command = "wpscan" in command[0]
            is_nmap_command = "nmap" in command[0]

            if is_nmap_command and process.returncode != 0 :
                 print_warning(f"Nmap command {' '.join(command)} finished with exit code {process.returncode}. Check logs and Nmap files.")
                 if process.stderr: print_warning(f"Nmap Stderr: {process.stderr[:200]}...")

            elif not is_wpscan_command or (is_wpscan_command and process.returncode in [1, 2]):
                print_warning(f"Command {' '.join(command)} finished with exit code {process.returncode}")
                print_warning(f"Stderr: {process.stderr[:200]}...") 
            elif is_wpscan_command and process.returncode == 4:
                print_error(f"WPScan found vulnerabilities for {' '.join(command)}. Output: {output_file}")
            elif is_wpscan_command and process.returncode == 5:
                 print_warning(f"WPScan reported an insecure WordPress instance for {' '.join(command)}. Output: {output_file}")
            else: 
                print_success(f"Finished: {' '.join(command)} (exit code {process.returncode}). Output saved to {output_file}")
        else: 
            print_success(f"Finished: {' '.join(command)}. Output saved to {output_file}")
        return process.stdout, process.stderr
    except FileNotFoundError:
        print_error(f"Command not found: {command[0]}. Please ensure it's installed and in PATH.")
        return None, None
    except Exception as e:
        print_error(f"Error running command {' '.join(command)}: {e}")
        return None, None

def create_dir(path):
    """Creates a directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)

# --- Scan Functions ---

def nmap_quick_scan(target_ip, target_name, scans_dir, nmap_ports_arg_to_use):
    """Runs Nmap quick scan to find open TCP ports."""
    print_header(f"Starting Nmap Quick Scan on {target_ip} with ports: {nmap_ports_arg_to_use}")
    nmap_dir = os.path.join(scans_dir, "nmap")
    create_dir(nmap_dir)
    # Base name for -oA output (Nmap will append .nmap, .gnmap, .xml)
    base_oA_path = os.path.join(nmap_dir, f"quickNmap_{target_name}")
    # .txt file for run_command to log stdout (which is Nmap's normal output)
    log_output_file = base_oA_path + ".txt" 
    
    command = ["nmap", "-sS", nmap_ports_arg_to_use, "-n", "-Pn", "--min-rate", "5000", "-oA", base_oA_path, target_ip]
    stdout, _ = run_command(command, log_output_file) 
    
    open_ports = []
    if stdout: # Parse from stdout (normal Nmap output)
        for line in stdout.splitlines():
            match = re.search(r"^(\d+)/tcp\s+open", line)
            if match:
                open_ports.append(match.group(1))
    if open_ports:
        print_success(f"Open TCP ports found: {', '.join(open_ports)}")
    else:
        print_warning("No open TCP ports found in quick scan.")
    return open_ports

def nmap_deep_scan(target_ip, target_name, open_ports_str, scans_dir):
    """Runs Nmap deep scan (-A) on specified ports."""
    if not open_ports_str:
        print_warning("No open ports to run Nmap deep scan on.")
        return None
    print_header(f"Starting Nmap Deep Scan on {target_ip} (Ports: {open_ports_str})")
    nmap_dir = os.path.join(scans_dir, "nmap")
    base_oA_path = os.path.join(nmap_dir, f"deepNmap_{target_name}")
    log_output_file = base_oA_path + ".txt"
    
    command = ["nmap", "-sS", "-A", "-p", open_ports_str, "-oA", base_oA_path, target_ip]
    stdout, _ = run_command(command, log_output_file)
    return stdout 

def nmap_scripts_scan(target_ip, target_name, open_ports_str, scans_dir):
    """Runs Nmap NSE scripts scan."""
    if not open_ports_str:
        print_warning("No open ports to run Nmap scripts scan on.")
        return
    print_header(f"Starting Nmap Scripts Scan on {target_ip} (Ports: {open_ports_str})")
    nmap_dir = os.path.join(scans_dir, "nmap")
    base_oA_path = os.path.join(nmap_dir, f"nse_{target_name}")
    log_output_file = base_oA_path + ".txt"
    
    command = ["nmap", "-sV", "-n", "-O", "--script", NMAP_NSE_SCRIPTS, "-p", open_ports_str, "-oA", base_oA_path, target_ip]
    run_command(command, log_output_file)

def nmap_udp_scan(target_ip, target_name, scans_dir):
    """Runs Nmap UDP scan."""
    print_header(f"Starting Nmap UDP Scan on {target_ip} (Top {NMAP_TOP_UDP_PORTS} ports)")
    nmap_dir = os.path.join(scans_dir, "nmap")
    base_oA_path = os.path.join(nmap_dir, f"udpNmap_{target_name}")
    log_output_file = base_oA_path + ".txt"

    command = ["nmap", "-sU", f"--top-ports={NMAP_TOP_UDP_PORTS}", "--version-all", "-oA", base_oA_path, target_ip]
    run_command(command, log_output_file)

def identify_web_services(nmap_deep_scan_output):
    """Parses Nmap deep scan output to identify HTTP/HTTPS services."""
    web_services = {} 
    if not nmap_deep_scan_output:
        return web_services
    for line in nmap_deep_scan_output.splitlines():
        match = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if match:
            port, service_field = match.groups()
            service_name_match = re.search(r"(\S+)\s+(.+)", line[match.end():]) 
            service_details = service_name_match.group(2) if service_name_match else "Unknown Web Service"
            if "http" in service_field and "ssl" not in service_field and "https" not in service_field:
                web_services[port] = {"protocol": "http", "service_details": service_details}
            elif "ssl/http" in service_field or "https" in service_field:
                web_services[port] = {"protocol": "https", "service_details": service_details}
    if web_services:
        print_success(f"Identified web services: {web_services}")
    else:
        print_warning("No specific HTTP/HTTPS services identified from Nmap deep scan. Web scans might be less targeted.")
    return web_services

def hakrawler_scan(protocol, host, port, target_name, web_scans_dir):
    """Runs Hakrawler."""
    print_info(f"Running Hakrawler on {protocol}://{host}:{port}")
    output_file = os.path.join(web_scans_dir, f"hakrawler_{protocol}_{port}_{target_name}.txt")
    url_to_crawl = f"{protocol}://{host}:{port}"
    try:
        hakrawler_command = ["hakrawler", "-insecure", "-d", "0", "-u"] 
        process = subprocess.Popen(['echo', url_to_crawl], stdout=subprocess.PIPE)
        hakrawler_process = subprocess.run(hakrawler_command, stdin=process.stdout, capture_output=True, text=True, check=False)
        process.wait()
        with open(output_file, "w") as f:
            f.write(f"Command: echo \"{url_to_crawl}\" | {' '.join(hakrawler_command)}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write("--- STDOUT ---\n")
            f.write(hakrawler_process.stdout)
            f.write("\n--- STDERR ---\n")
            f.write(hakrawler_process.stderr)
        if hakrawler_process.returncode != 0:
            print_warning(f"Hakrawler on {url_to_crawl} finished with exit code {hakrawler_process.returncode}")
        else:
            print_success(f"Hakrawler on {url_to_crawl} done. Output: {output_file}")
    except FileNotFoundError:
        print_error("Hakrawler not found. Please ensure it's installed and in PATH.")
    except Exception as e:
        print_error(f"Error running Hakrawler on {url_to_crawl}: {e}")

def nikto_scan(protocol, host, port, target_name, web_scans_dir):
    """Runs Nikto scan."""
    print_info(f"Running Nikto on {protocol}://{host}:{port}")
    output_file = os.path.join(web_scans_dir, f"nikto_{protocol}_{port}_{target_name}.txt")
    command = ["nikto", "-h", host, "-p", port, "-maxtime", NIKTO_MAXTIME, "-ask", "no", "-Format", "txt", "-o", "-"]
    if protocol == "https":
        command.append("-ssl")
    try:
        print_info(f"Running: {' '.join(command)}")
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        with open(output_file, "w") as f:
            f.write(f"Command: {' '.join(command)}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write("--- STDOUT ---\n")
            f.write(process.stdout) 
            if process.stderr: 
                f.write("\n--- STDERR ---\n")
                f.write(process.stderr)
        if "0 host(s) tested" in process.stdout or process.returncode != 0 : 
            print_warning(f"Nikto on {protocol}://{host}:{port} reported no hosts tested or an error. Check {output_file}.")
            if os.path.getsize(output_file) < 200 : 
                 pass 
        else:
            print_success(f"Nikto on {protocol}://{host}:{port} done. Output: {output_file}")
    except FileNotFoundError:
        print_error("Nikto not found. Please ensure it's installed and in PATH.")
    except Exception as e:
        print_error(f"Error running Nikto: {e}")

def robots_txt_scan(protocol, host, port, target_name, web_scans_dir):
    """Downloads robots.txt and determines its status."""
    url = f"{protocol}://{host}:{port}/robots.txt"
    print_info(f"Fetching robots.txt from {url}")
    output_file = os.path.join(web_scans_dir, f"robots_{protocol}_{port}_{target_name}.txt")
    curl_log_file = output_file + ".curl_log"
    command = ["curl", "-sSikL", "-m", "10", url] 
    try:
        print_info(f"Running: {' '.join(command)}")
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        with open(curl_log_file, "w") as f_log:
            f_log.write(f"Command: {' '.join(command)}\n")
            f_log.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f_log.write(f"Return Code: {process.returncode}\n")
            f_log.write("--- STDOUT ---\n")
            f_log.write(process.stdout)
            f_log.write("\n--- STDERR ---\n")
            f_log.write(process.stderr)
        if process.returncode == 0:  
            is_404 = False
            if process.stdout:
                header_part = process.stdout.split('\r\n\r\n', 1)[0]
                if re.search(r"^HTTP/\d(\.\d)?\s+404", header_part, re.IGNORECASE | re.MULTILINE):
                    is_404 = True
            if is_404:
                message = f"robots.txt NOT found (HTTP 404 status received) at {url}."
                print_warning(message)
                with open(output_file, "w") as f:
                    f.write(f"# {message}\n")
                    f.write(f"# Full curl output (including 404 page headers/body) in {curl_log_file}\n")
            elif not process.stdout.strip():  
                message = f"robots.txt seems BLANK or EMPTY (curl success, non-404, but empty response) at {url}."
                print_warning(message)
                with open(output_file, "w") as f:
                    f.write(f"# {message}\n")
                    f.write(f"# Full curl output in {curl_log_file}\n")
            else:  
                print_success(f"robots.txt FOUND at {url}.")
                with open(output_file, "w") as f:
                    f.write(process.stdout)
        else:  
            message = f"robots.txt NOT found (curl command failed with exit code {process.returncode}) at {url}."
            print_error(message)
            if process.stderr.strip():
                print_error(f"Curl stderr: {process.stderr.strip()[:200]}...")
            with open(output_file, "w") as f:
                f.write(f"# {message}\n")
                f.write(f"# Exit code: {process.returncode}\n")
                if process.stderr.strip():
                    f.write(f"# Curl stderr: {process.stderr.strip()}\n")
                f.write(f"# Full curl execution details in {curl_log_file}\n")
    except FileNotFoundError: 
        message = f"curl command not found. Please ensure it's installed and in PATH. Cannot fetch robots.txt for {url}"
        print_error(message)
        with open(output_file, "w") as f:
            f.write(f"# {message}\n")
    except Exception as e: 
        message = f"An unexpected error occurred while trying to fetch robots.txt from {url}: {e}"
        print_error(message)
        with open(output_file, "w") as f:
            f.write(f"# {message}\n")
            f.write(f"# Details logged in {curl_log_file} if curl execution started.\n")

def whatweb_scan(protocol, host, port, target_name, web_scans_dir):
    """Runs WhatWeb scan."""
    url = f"{protocol}://{host}:{port}"
    print_info(f"Running WhatWeb on {url}")
    output_file = os.path.join(web_scans_dir, f"whatweb_{protocol}_{port}_{target_name}.txt")
    command = ["whatweb", "-a", WHATWEB_AGGRESSION, "-v", "--color=never", "--no-error", url]
    run_command(command, output_file)
    return output_file 

def wpscan_scan(protocol, host, port, target_name, web_scans_dir, api_token):
    """Runs WPScan."""
    url = f"{protocol}://{host}:{port}"
    print_info(f"Running WPScan on {url}")
    output_file = os.path.join(web_scans_dir, f"wpscan_{protocol}_{port}_{target_name}.txt")
    command = [
        "wpscan", "--url", url,
        "--enumerate", "vp,vt,u1-100", 
        "--random-user-agent",
        "--disable-tls-checks", 
        "--force", 
        "-f", "cli-no-color", 
        "-o", output_file
    ]
    if api_token:
        command.extend(["--api-token", api_token])
    else:
        print_warning("No WPScan API token provided. Vulnerability data will be limited. Get one from wpscan.com.")
    run_command(command, output_file)

def check_wordpress_and_run_wpscan(whatweb_output_file, protocol, host, port, target_name, web_scans_dir, wpscan_api_token):
    """Checks WhatWeb output for WordPress and runs WPScan if detected."""
    if not os.path.exists(whatweb_output_file):
        print_warning(f"WhatWeb output file not found: {whatweb_output_file}. Skipping WPScan check for {protocol}://{host}:{port}")
        return
    try:
        with open(whatweb_output_file, "r") as f:
            whatweb_content = f.read()
        if re.search(r"WordPress", whatweb_content, re.IGNORECASE):
            print_success(f"WordPress detected by WhatWeb on {protocol}://{host}:{port}. Running WPScan.")
            wpscan_scan(protocol, host, port, target_name, web_scans_dir, wpscan_api_token)
        else:
            print_info(f"WordPress not detected by WhatWeb on {protocol}://{host}:{port}. Skipping WPScan.")
    except Exception as e:
        print_error(f"Error reading or parsing WhatWeb output {whatweb_output_file} for WPScan check: {e}")

def process_feroxbuster_output_and_verb_enum(protocol, host, port, target_name, scans_dir, ferox_output_filepath):
    """Reads Feroxbuster output, performs verb enumeration, and saves summaries."""
    print_header(f"Processing Feroxbuster Output & Verb Enumeration for {protocol}://{host}:{port}")
    web_scans_dir = os.path.join(scans_dir, protocol) 
    create_dir(web_scans_dir) 

    if not os.path.exists(ferox_output_filepath) or os.path.getsize(ferox_output_filepath) == 0:
        print_error(f"Feroxbuster output file not found or empty: {ferox_output_filepath}")
        print_warning("Skipping verb enumeration and summary for this target.")
        return

    verb_enum_output_file = os.path.join(web_scans_dir, f"verbs_{protocol}_{port}_{target_name}.txt")
    ferox_url_status_summary_file = os.path.join(web_scans_dir, f"ferox_url_status_summary_{protocol}_{port}_{target_name}.txt")
    
    unique_urls_for_verb_enum = set()
    ferox_findings_for_summary = [] 

    try:
        with open(ferox_output_filepath, "r") as f_ferox:
            for line in f_ferox:
                line = line.strip()
                if not line or line.startswith("#") or \
                   line.startswith("---") or \
                   "Configuration {" in line or \
                   line.strip() == "}" or \
                   line.startswith("MSG") or \
                   "finished scanning" in line.lower() or \
                   "Starting feroxbuster" in line or \
                   "Using wordlist" in line or \
                   "Target URL" in line or \
                   "Threads" in line or \
                   "Status Codes" in line or \
                   "Timeout" in line or \
                   "User-Agent" in line or \
                   "Extensions" in line or \
                   "Could not connect" in line or \
                   "Errored" in line.lower() or \
                   "Press ENTER to continue..." in line:
                    continue
                
                match = re.match(r"^\s*(\d{3})\s+([A-Z]+)\s+.*? (https?://\S+)", line)
                if match:
                    status_code = match.group(1)
                    url_candidate = match.group(3)
                    target_base_url_for_check = f"{protocol}://{host}"
                    if not ((protocol == "http" and port == "80") or (protocol == "https" and port == "443")):
                        target_base_url_for_check += f":{port}"
                    if url_candidate.startswith(target_base_url_for_check):
                        ferox_findings_for_summary.append((url_candidate, status_code))
                        unique_urls_for_verb_enum.add(url_candidate)
    except Exception as e:
        print_error(f"Error reading Feroxbuster output file {ferox_output_filepath}: {e}")
        return 

    if not unique_urls_for_verb_enum and not ferox_findings_for_summary:
        print_warning(f"No suitable URLs/findings parsed from Feroxbuster output ({ferox_output_filepath}) for verb enumeration or summary.")
        return

    if unique_urls_for_verb_enum:
        print_info(f"Found {len(unique_urls_for_verb_enum)} unique URLs for verb enumeration from {ferox_output_filepath}.")
        with open(verb_enum_output_file, "w") as f_verb:
            f_verb.write(f"# HTTP Verb Enumeration for {protocol}://{host}:{port}\n")
            f_verb.write(f"# Based on Feroxbuster output: {ferox_output_filepath}\n")
            f_verb.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")
            for url_to_check in sorted(list(unique_urls_for_verb_enum)):
                print_info(f"Verb check: {url_to_check}")
                f_verb.write(f"URL: {url_to_check}\n")
                try:
                    curl_cmd = ["curl", "-sSik", "-X", "OPTIONS", url_to_check, "--connect-timeout", "5"]
                    process = subprocess.run(curl_cmd, capture_output=True, text=True, check=False)
                    f_verb.write("--- Response Headers ---\n")
                    f_verb.write(process.stdout) 
                    f_verb.write("\n")
                    allow_header = None
                    for header_line in process.stdout.splitlines():
                        if header_line.lower().startswith("allow:"):
                            allow_header = header_line.split(":", 1)[1].strip()
                            break
                    if allow_header:
                        f_verb.write(f"Allowed Methods: {allow_header}\n")
                        print_success(f"  Allowed Methods for {url_to_check}: {allow_header}")
                    else:
                        f_verb.write("Allowed Methods: Not found or N/A\n")
                        print_warning(f"  Allowed Methods for {url_to_check}: Not found")
                    f_verb.write("------------------------\n\n")
                except Exception as e:
                    error_msg = f"Error during verb check for {url_to_check}: {e}\n"
                    print_error(error_msg)
                    f_verb.write(error_msg)
                    f_verb.write("------------------------\n\n")
        print_success(f"Verb enumeration complete. Results: {verb_enum_output_file}")
    else:
        print_warning(f"No unique URLs found for verb enumeration from {ferox_output_filepath}.")

    if ferox_findings_for_summary:
        print_info(f"Creating Feroxbuster URL-Status summary file for {len(ferox_findings_for_summary)} findings from {ferox_output_filepath}.")
        with open(ferox_url_status_summary_file, "w") as f_summary:
            f_summary.write(f"# Feroxbuster URL and Status Code Summary for {protocol}://{host}:{port}\n")
            f_summary.write(f"# Source Feroxbuster output: {ferox_output_filepath}\n")
            f_summary.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")
            f_summary.write("URL Response_Code\n")
            f_summary.write("-------------------\n")
            for url_val, status_code in ferox_findings_for_summary: 
                f_summary.write(f"{url_val} {status_code}\n")
        print_success(f"Feroxbuster URL-Status summary created: {ferox_url_status_summary_file}")
    else:
        print_warning(f"No findings from Feroxbuster in {ferox_output_filepath} to create a summary file.")

def enum4linux_scan(target_ip, target_name, scans_dir):
    """Runs enum4linux if SMB/LDAP ports are open."""
    print_header(f"Starting Enum4linux on {target_ip}")
    smb_dir = os.path.join(scans_dir, "smb")
    create_dir(smb_dir)
    output_file = os.path.join(smb_dir, f"enum4linux_{target_name}.txt")
    command = ["enum4linux", "-a", "-M", "-l", "-d", target_ip] 
    run_command(command, output_file)

def smbmap_scan(target_ip, target_name, scans_dir, port):
    """Runs various smbmap commands against a target SMB port."""
    print_header(f"Starting SMBMap scans on {target_ip}:{port}")
    smb_dir = os.path.join(scans_dir, "smb")
    create_dir(smb_dir)

    commands_to_run = [
        {
            "cmd_args": ["smbmap", "-H", target_ip, "-P", str(port)],
            "outfile_suffix": f"share-permissions_default_user_port{port}"
        },
        {
            "cmd_args": ["smbmap", "-u", "null", "-p", "", "-H", target_ip, "-P", str(port)],
            "outfile_suffix": f"share-permissions_null_session_port{port}"
        },
        {
            "cmd_args": ["smbmap", "-H", target_ip, "-P", str(port), "-r"],
            "outfile_suffix": f"list-contents_default_user_port{port}"
        },
        {
            "cmd_args": ["smbmap", "-u", "null", "-p", "", "-H", target_ip, "-P", str(port), "-r"],
            "outfile_suffix": f"list-contents_null_session_port{port}"
        },
        {
            "cmd_args": ["smbmap", "-H", target_ip, "-P", str(port), "-x", "ipconfig /all"],
            "outfile_suffix": f"exec-ipconfig_default_user_port{port}"
        },
        {
            "cmd_args": ["smbmap", "-u", "null", "-p", "", "-H", target_ip, "-P", str(port), "-x", "ipconfig /all"],
            "outfile_suffix": f"exec-ipconfig_null_session_port{port}"
        }
    ]

    for item in commands_to_run:
        output_file = os.path.join(smb_dir, f"smbmap_{item['outfile_suffix']}_{target_name}.txt")
        run_command(item["cmd_args"], output_file)
    print_success(f"SMBMap scans on {target_ip}:{port} completed.")


def clone_ftp_scan(target_ip, target_name, scans_dir):
    """Clones anonymous FTP using wget."""
    print_header(f"Attempting to clone anonymous FTP from {target_ip}")
    ftp_dir = os.path.join(scans_dir, "ftp", f"ftp_clone_{target_name}")
    create_dir(ftp_dir) 
    output_log_file = os.path.join(scans_dir, "ftp", f"wget_ftp_log_{target_name}.txt")
    command = ["wget", "-m", f"ftp://anonymous@{target_ip}", "-P", ftp_dir, "--passive-ftp", "-nv"] 
    print_info(f"Running: {' '.join(command)}")
    print_info(f"FTP files will be downloaded to: {ftp_dir}")
    print_info(f"Wget logs will be saved to: {output_log_file}")
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False) 
        with open(output_log_file, "w") as f:
            f.write(f"Command: {' '.join(command)}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write("--- WGET LOG (STDOUT) ---\n")
            f.write(process.stdout)
            f.write("\n--- WGET LOG (STDERR) ---\n")
            f.write(process.stderr) 
        if process.returncode != 0 and "ERROR 550" not in process.stderr and "Login failed" not in process.stderr : 
            print_warning(f"wget command finished with exit code {process.returncode}. Check logs: {output_log_file}")
            print_warning(f"Stderr snippet: {process.stderr[:200]}...")
        else:
            if any(os.scandir(ftp_dir)):
                 print_success(f"FTP clone attempt done. Files in {ftp_dir}. Log: {output_log_file}")
            else:
                 print_warning(f"FTP clone attempt done, but {ftp_dir} appears empty or login failed. Log: {output_log_file}")
    except FileNotFoundError:
        print_error("wget not found. Please ensure it's installed and in PATH.")
    except Exception as e:
        print_error(f"Error running wget for FTP clone: {e}")

# --- Main Function ---
def main():
    parser = argparse.ArgumentParser(description="Python Enumeration Script inspired by PortCartographer.")
    parser.add_argument("target_ip", help="IP address of the target.")
    parser.add_argument("target_name", help="Target name, a directory will be created using this.")
    parser.add_argument("-H", "--hostname", help="Specify hostname (FQDN). If not provided, target_ip is used as hostname.", default=None)
    parser.add_argument("-O", "--os", choices=["Linux", "Windows", "Unknown"], default="Unknown", help="Specify OS type for Feroxbuster wordlists.")
    parser.add_argument("--nmap-ports", default=NMAP_QUICK_SCAN_PORTS_ARG, help=f"Nmap port argument for initial quick scan (e.g., '-p80,443', '--top-ports 100'). Default: '{NMAP_QUICK_SCAN_PORTS_ARG}'")
    parser.add_argument("--wpscan-api-token", default=WPSCAN_API_TOKEN, help="WPScan API token from wpscan.com for vulnerability data.")

    args = parser.parse_args()

    target_ip = args.target_ip
    target_name = args.target_name
    hostname = args.hostname if args.hostname else target_ip
    os_type = args.os
    wpscan_api_token = args.wpscan_api_token 

    print_header(f"Starting Enumeration for Target: {target_ip} (Name: {target_name}, Hostname: {hostname})")

    base_dir = target_name
    scans_dir = os.path.join(base_dir, "Scans")
    if os.path.exists(base_dir):
        print_warning(f"Directory '{base_dir}' already exists. Results may be overwritten or appended.")
    create_dir(base_dir)
    create_dir(scans_dir)
    
    with open(os.path.join(base_dir, f"notes_{target_name}.txt"), "a") as f:
        f.write(f"Enumeration started: {datetime.now().isoformat()}\n")
        f.write(f"Target IP: {target_ip}\n")
        f.write(f"Target Name: {target_name}\n")
        f.write(f"Hostname: {hostname}\n")
        f.write(f"Assumed OS for Feroxbuster: {os_type}\n\n")

    # Determine Nmap ports for quick scan (interactive prompt)
    nmap_ports_default_for_prompt = args.nmap_ports 
    prompt_message = (
        f"Enter Nmap port argument for initial quick scan (e.g., '-p80,443', '--top-ports 100').\n"
        f"Default: [{nmap_ports_default_for_prompt}]: "
    )
    user_input_nmap_ports = input(prompt_message).strip()
    
    final_nmap_ports_to_use = user_input_nmap_ports if user_input_nmap_ports else nmap_ports_default_for_prompt

    open_tcp_ports = nmap_quick_scan(target_ip, target_name, scans_dir, final_nmap_ports_to_use)
    
    if not open_tcp_ports:
        print_error("No open TCP ports found by Nmap quick scan. Further TCP-based scans will be limited or skipped.")
        nmap_udp_scan(target_ip, target_name, scans_dir) # Run UDP scan even if no TCP ports
        print_header("Enumeration finished due to no open TCP ports.")
        return

    open_ports_str = ",".join(open_tcp_ports)
    
    nmap_deep_scan_output = nmap_deep_scan(target_ip, target_name, open_ports_str, scans_dir)
    nmap_scripts_scan(target_ip, target_name, open_ports_str, scans_dir)
    
    web_services_on_ports = identify_web_services(nmap_deep_scan_output)
    
    feroxbuster_tasks_to_prompt = [] 

    if web_services_on_ports:
        print_header("Starting Initial Web Application Scans (excluding Feroxbuster)")
        for port, service_info in web_services_on_ports.items():
            protocol = service_info["protocol"]
            print_info(f"Targeting web service on port {port} ({protocol}) - {service_info['service_details']}")
            
            web_protocol_scans_dir = os.path.join(scans_dir, protocol) 
            create_dir(web_protocol_scans_dir)

            hakrawler_scan(protocol, hostname, port, target_name, web_protocol_scans_dir)
            nikto_scan(protocol, hostname, port, target_name, web_protocol_scans_dir)
            robots_txt_scan(protocol, hostname, port, target_name, web_protocol_scans_dir) 
            
            whatweb_output_file_path = whatweb_scan(protocol, hostname, port, target_name, web_protocol_scans_dir)
            if whatweb_output_file_path: 
                 check_wordpress_and_run_wpscan(whatweb_output_file_path, protocol, hostname, port, target_name, web_protocol_scans_dir, wpscan_api_token)
            
            wordlist, extensions = "", ""
            if os_type == "Linux":
                wordlist = FEROXBUSTER_WORDLIST_LINUX
                extensions = FEROXBUSTER_EXTENSIONS_LINUX
            elif os_type == "Windows":
                wordlist = FEROXBUSTER_WORDLIST_WINDOWS
                extensions = FEROXBUSTER_EXTENSIONS_WINDOWS
            else: 
                wordlist = FEROXBUSTER_WORDLIST_UNKNOWN
                extensions = FEROXBUSTER_EXTENSIONS_UNKNOWN

            if not os.path.exists(wordlist):
                print_error(f"Feroxbuster wordlist not found: {wordlist}. Skipping Feroxbuster for {protocol}://{hostname}:{port}.")
            else:
                ferox_output_filename = f"feroxbuster_dir_{protocol}_{port}_{target_name}.txt"
                ferox_output_filepath = os.path.join(web_protocol_scans_dir, ferox_output_filename)
                ferox_command_str = (
                    f"feroxbuster -u {protocol}://{hostname}:{port} -w {wordlist} -x {extensions} "
                    f"-t {FEROXBUSTER_THREADS} -k --dont-scan '/(js|css|images|img|icons)' "
                    f"--filter-status 404 --extract-links --scan-dir-listings -o {ferox_output_filepath}" 
                )
                feroxbuster_tasks_to_prompt.append({
                    'command_str': ferox_command_str,
                    'output_filepath': ferox_output_filepath,
                    'protocol': protocol,
                    'host': hostname,
                    'port': port,
                    'target_name': target_name,
                    'scans_dir': scans_dir 
                })
    else:
        print_warning("No specific web services identified by Nmap. Skipping web application scans.")

    # SMB related scans
    smb_ports_to_scan = {'139', '445'} 
    actual_smb_ports_found = [p for p in open_tcp_ports if p in smb_ports_to_scan]

    if actual_smb_ports_found:
        print_info(f"SMB related port(s) found: {', '.join(actual_smb_ports_found)}. Running Enum4linux and SMBMap.")
        enum4linux_scan(target_ip, target_name, scans_dir) 
        for smb_port in actual_smb_ports_found:
            smbmap_scan(target_ip, target_name, scans_dir, smb_port)
    else:
        print_info("No common SMB ports (139, 445) found in quick scan. Skipping Enum4linux and SMBMap.")


    if '21' in open_tcp_ports:
        print_info("FTP port (21) found. Attempting anonymous FTP clone.")
        clone_ftp_scan(target_ip, target_name, scans_dir)
    else:
        print_info("FTP port (21) not found in quick scan. Skipping FTP clone.")

    # Prompt for Feroxbuster commands if any are queued
    if feroxbuster_tasks_to_prompt:
        print_warning("\n--- FEROXBUSTER ACTION REQUIRED ---")
        print_info("Please run the following Feroxbuster command(s) in SEPARATE terminal(s) or use feroxBuilder.py later:")
        for task in feroxbuster_tasks_to_prompt:
            print(f"\n{TermColors.BOLD}{task['command_str']}{TermColors.ENDC}")
            print_info(f"This command is configured to save its output to: {TermColors.UNDERLINE}{task['output_filepath']}{TermColors.ENDC}")
    else:
        print_info("No Feroxbuster tasks to run based on initial web service discovery.")

    # Run Nmap UDP Scan (runs after Feroxbuster commands are displayed, before user is prompted to confirm Ferox completion)
    nmap_udp_scan(target_ip, target_name, scans_dir)

    # Wait for Feroxbuster completion and process outputs if tasks were prompted
    if feroxbuster_tasks_to_prompt:
        input(f"\n{TermColors.WARNING}Press Enter here AFTER ALL displayed Feroxbuster commands have finished and their output files are saved.{TermColors.ENDC}")
        for task in feroxbuster_tasks_to_prompt:
            process_feroxbuster_output_and_verb_enum(
                task['protocol'], task['host'], task['port'], task['target_name'], 
                task['scans_dir'], task['output_filepath']
            )
    
    print_header(f"Enumeration for {target_name} completed!")
    print_info(f"All results saved in directory: {base_dir}")

if __name__ == "__main__":
    main()
