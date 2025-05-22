#!/usr/bin/env python3

import subprocess
import os
import re
import argparse
from datetime import datetime
from urllib.parse import urlparse, urljoin

# --- Configuration ---
# Seclists base path (adjust if your Seclists are elsewhere)
SECLISTS_BASE_PATH = "/usr/share/seclists/Discovery/Web-Content/"
DEFAULT_WORDLISTS = {
    "small": os.path.join(SECLISTS_BASE_PATH, "directory-list-2.3-small.txt"),
    "medium": os.path.join(SECLISTS_BASE_PATH, "directory-list-2.3-medium.txt"),
    "large": os.path.join(SECLISTS_BASE_PATH, "directory-list-2.3-big.txt"),
    "raft-small": os.path.join(SECLISTS_BASE_PATH, "raft-small-directories.txt"),
    "raft-medium": os.path.join(SECLISTS_BASE_PATH, "raft-medium-directories.txt"), # Assuming this path
    "raft-large": os.path.join(SECLISTS_BASE_PATH, "raft-large-directories.txt"),   # Assuming this path
}
DEFAULT_EXTENSIONS = "php,html,txt,pdf,sh"
DEFAULT_THREADS = "50"
DEFAULT_OUTPUT_DIR_NAME_SUFFIX = "ferox_verb_results" 

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
def create_dir(path):
    """Creates a directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)

def get_user_input(prompt, default_value=None):
    """Gets user input with an optional default value."""
    if default_value is not None: 
        prompt_with_default = f"{prompt} [{default_value}]: "
    else:
        prompt_with_default = f"{prompt}: "
    
    user_val = input(prompt_with_default).strip()
    if not user_val and default_value is not None:
        return default_value
    return user_val

# --- Main Logic ---
def main():
    # Define wordlist choices based on the keys in DEFAULT_WORDLISTS
    wordlist_choice_options = list(DEFAULT_WORDLISTS.keys()) + ['custom']

    parser = argparse.ArgumentParser(description="Feroxbuster Command Builder & Verb Enumerator.")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://target.com:8080).")
    parser.add_argument("-wl", "--wordlist-choice", choices=wordlist_choice_options, default='small', 
                        help=f"Wordlist choice ({', '.join(wordlist_choice_options)}). Default: small.")
    parser.add_argument("-cwl", "--custom-wordlist", help="Path to custom wordlist (if --wordlist-choice is 'custom').")
    parser.add_argument("-x", "--extensions", default=DEFAULT_EXTENSIONS, help=f"Comma-separated extensions for Feroxbuster (default: {DEFAULT_EXTENSIONS}).")
    parser.add_argument("-t", "--threads", default=DEFAULT_THREADS, help=f"Number of threads for Feroxbuster (default: {DEFAULT_THREADS}).")
    parser.add_argument("-o", "--output-dir", help="Directory to save output files. If not provided, a default will be generated.")
    parser.add_argument("--ferox-output-file", help="Path to an existing Feroxbuster output file to process (skips Feroxbuster command generation and execution prompt).")

    args = parser.parse_args()

    target_url = args.url
    parsed_url = urlparse(target_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print_error("Invalid target URL. Please include scheme (http/https) and hostname.")
        return

    target_hostname = parsed_url.hostname 

    output_dir = ""
    ferox_output_filepath = ""

    if args.ferox_output_file:
        ferox_output_filepath = args.ferox_output_file
        if not os.path.exists(ferox_output_filepath):
            print_error(f"Provided Feroxbuster output file not found: {ferox_output_filepath}")
            return
        print_info(f"Processing existing Feroxbuster output file: {ferox_output_filepath}")
        
        if args.output_dir:
            output_dir = args.output_dir
        else:
            output_dir_candidate = os.path.dirname(ferox_output_filepath)
            if not output_dir_candidate: 
                 sanitized_target_name = re.sub(r'[^a-zA-Z0-9_-]', '_', parsed_url.netloc or "target")
                 output_dir = f"{sanitized_target_name}_{DEFAULT_OUTPUT_DIR_NAME_SUFFIX}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            else:
                output_dir = output_dir_candidate
        create_dir(output_dir)
        print_info(f"Verb/summary results will be saved in: {os.path.abspath(output_dir)}")

    else:
        print_header("--- Feroxbuster Command Configuration ---")

        wordlist_choice = get_user_input(f"Select wordlist type ({', '.join(wordlist_choice_options)})", args.wordlist_choice)
        if wordlist_choice not in wordlist_choice_options:
            print_warning(f"Invalid wordlist choice '{wordlist_choice}'. Using default '{args.wordlist_choice}'.")
            wordlist_choice = args.wordlist_choice
        
        wordlist_path = ""
        if wordlist_choice == 'custom':
            custom_wl_default = args.custom_wordlist if args.custom_wordlist else None
            wordlist_path = get_user_input("Enter path to custom wordlist", custom_wl_default)
            if not wordlist_path:
                 print_error("Custom wordlist path is required when 'custom' type is selected and no path is provided.")
                 return
        else:
            wordlist_path = DEFAULT_WORDLISTS.get(wordlist_choice)

        if not wordlist_path or not os.path.exists(wordlist_path):
            print_error(f"Wordlist not found or path invalid: {wordlist_path}")
            print_warning(f"Please ensure Seclists are installed at {SECLISTS_BASE_PATH} or provide a valid custom path.")
            return

        extensions = get_user_input(f"Comma-separated extensions (e.g., php,html)", args.extensions)
        
        threads_input = get_user_input(f"Number of threads", str(args.threads))
        try:
            threads_val = int(threads_input)
            if threads_val <= 0: raise ValueError("Threads must be positive")
            threads = str(threads_val)
        except ValueError:
            print_warning(f"Invalid thread count '{threads_input}'. Using default '{args.threads}'.")
            threads = str(args.threads)

        sanitized_target_name = re.sub(r'[^a-zA-Z0-9_-]', '_', parsed_url.netloc or "target")
        calculated_default_output_dir = f"{sanitized_target_name}_{DEFAULT_OUTPUT_DIR_NAME_SUFFIX}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        output_dir_default_for_prompt = args.output_dir if args.output_dir else calculated_default_output_dir
        output_dir = get_user_input("Enter output directory name", output_dir_default_for_prompt)
        
        create_dir(output_dir)
        print_info(f"Results will be saved in: {os.path.abspath(output_dir)}")

        ferox_output_filename = f"feroxbuster_output_{parsed_url.hostname or 'target'}.txt"
        ferox_output_filepath = os.path.join(output_dir, ferox_output_filename)

        ferox_command_parts = [
            "feroxbuster", "-u", target_url, "-w", wordlist_path, "-t", threads
        ]
        if extensions: 
            ferox_command_parts.extend(["-x", extensions])
        
        ferox_command_parts.extend([
            "-k", "--dont-scan", "/(js|css|images|img|icons)", 
            "--filter-status", "404", "--extract-links", "--scan-dir-listings",
            "-o", ferox_output_filepath
        ])
        ferox_command_str = " ".join(ferox_command_parts)

        print_warning("\n--- FEROXBUSTER ACTION REQUIRED ---")
        print_info(f"Please run the following Feroxbuster command in a SEPARATE terminal:")
        print(f"\n{TermColors.BOLD}{ferox_command_str}{TermColors.ENDC}\n")
        print_info(f"This command is configured to save its output to: {TermColors.UNDERLINE}{ferox_output_filepath}{TermColors.ENDC}")
        input(f"{TermColors.WARNING}Press Enter here AFTER Feroxbuster has finished and its output file is saved.{TermColors.ENDC}")

        if not os.path.exists(ferox_output_filepath) or os.path.getsize(ferox_output_filepath) == 0:
            print_error(f"Feroxbuster output file not found or empty: {ferox_output_filepath}")
            print_warning("Cannot proceed with verb enumeration.")
            return

    print_info(f"Processing Feroxbuster output from: {ferox_output_filepath}")

    verb_enum_summary_file = os.path.join(output_dir, "verbs_summary.txt")
    url_status_summary_file = os.path.join(output_dir, "ferox_url_status_summary.txt")

    ferox_line_regex = re.compile(r"^\s*([A-Z]+)\s+(\d{3})\s+\S+l\s+\S+w\s+\S+c\s+(https?://\S+)(?:\s*->\s*(.*))?$")
    
    relevant_status_codes_for_verb_enum = list(range(200, 300)) + [401] 
    redirect_status_codes = list(range(300, 400))

    all_ferox_findings = [] 
    urls_for_verb_enum = set()

    try:
        with open(ferox_output_filepath, "r") as f_ferox:
            for line in f_ferox:
                line = line.strip()
                match = ferox_line_regex.match(line)
                if match:
                    method, status_str, original_url, redirect_location = match.groups()
                    status_code = int(status_str)
                    
                    all_ferox_findings.append((original_url, status_code, redirect_location))

                    if status_code in relevant_status_codes_for_verb_enum:
                        urls_for_verb_enum.add(original_url)
                    elif status_code in redirect_status_codes and redirect_location:
                        if urlparse(redirect_location).netloc: 
                            final_url = redirect_location
                        else: 
                            final_url = urljoin(original_url, redirect_location)
                        
                        parsed_final_url = urlparse(final_url)
                        if parsed_final_url.hostname in ["localhost", "127.0.0.1"] and \
                           target_hostname not in ["localhost", "127.0.0.1"]:
                            final_url_port = parsed_final_url.port or parsed_url.port 
                            final_url = parsed_final_url._replace(netloc=f"{target_hostname}:{final_url_port}").geturl()
                        
                        urls_for_verb_enum.add(final_url)
    except Exception as e:
        print_error(f"Error reading or parsing Feroxbuster output file {ferox_output_filepath}: {e}")
        return

    if not urls_for_verb_enum:
        print_warning("No suitable URLs found in Feroxbuster output for verb enumeration.")
    else:
        print_info(f"Found {len(urls_for_verb_enum)} unique URLs for verb enumeration.")
        with open(verb_enum_summary_file, "w") as f_verb:
            f_verb.write(f"# HTTP Verb Enumeration for {target_url}\n")
            f_verb.write(f"# Based on Feroxbuster output: {ferox_output_filepath}\n")
            f_verb.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")

            for url_to_check in sorted(list(urls_for_verb_enum)):
                print_info(f"Verb check: {url_to_check}")
                f_verb.write(f"URL: {url_to_check}\n")
                try:
                    curl_cmd = ["curl", "-sSik", "-X", "OPTIONS", url_to_check, "--connect-timeout", "5"]
                    process = subprocess.run(curl_cmd, capture_output=True, text=True, check=False)
                    
                    stdout_lines = process.stdout.splitlines()
                    http_status_line_options = ""
                    allow_methods = ""

                    for header_line in stdout_lines:
                        if header_line.lower().startswith("http/"):
                            http_status_line_options = header_line 
                        elif header_line.lower().startswith("allow:"):
                            allow_methods = header_line.split(":", 1)[1].strip()
                    
                    f_verb.write(f"  OPTIONS Status: {http_status_line_options or 'Not found'}\n")
                    is_options_404 = "404 Not Found" in http_status_line_options

                    if allow_methods:
                        f_verb.write(f"  Allowed Methods: {allow_methods}\n")
                        if not is_options_404:
                             print_success(f"  Allowed Methods for {url_to_check}: {allow_methods} (Status: {http_status_line_options})")
                        else:
                             print_warning(f"  Allowed Methods for {url_to_check}: {allow_methods} (BUT OPTIONS Status: {http_status_line_options})")
                    elif not is_options_404 and http_status_line_options: 
                        f_verb.write(f"  Allowed Methods: Not explicitly found (OPTIONS Status: {http_status_line_options})\n")
                        print_warning(f"  OPTIONS request to {url_to_check} succeeded but no Allow header found (Status: {http_status_line_options}).")
                    else: 
                        f_verb.write(f"  Allowed Methods: Not found or OPTIONS request failed.\n")
                        print_warning(f"  Could not determine allowed methods for {url_to_check} (OPTIONS Status: {http_status_line_options or 'Error'}).")
                    f_verb.write("---\n")

                except Exception as e:
                    error_msg = f"Error during verb check for {url_to_check}: {e}"
                    print_error(error_msg)
                    f_verb.write(f"  Error: {error_msg}\n---\n")
        print_success(f"Verb enumeration complete. Results: {verb_enum_summary_file}")

    if all_ferox_findings:
        print_info(f"Creating Feroxbuster URL-Status summary file for {len(all_ferox_findings)} findings.")
        with open(url_status_summary_file, "w") as f_summary:
            f_summary.write(f"# Feroxbuster URL and Status Code Summary for {target_url}\n")
            f_summary.write(f"# Source Feroxbuster output: {ferox_output_filepath}\n")
            f_summary.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")
            f_summary.write("Original_URL Status_Code Redirect_Location (if any)\n")
            f_summary.write("-----------------------------------------------------\n")
            for orig_url, status, redir_loc in all_ferox_findings:
                f_summary.write(f"{orig_url} {status} {redir_loc if redir_loc else ''}\n")
        print_success(f"Feroxbuster URL-Status summary created: {url_status_summary_file}")
    else:
        print_warning("No findings from Feroxbuster to create a summary file.")
    
    print_header(f"Processing for {target_url} complete. Check directory: {os.path.abspath(output_dir)}")

if __name__ == "__main__":
    main()
