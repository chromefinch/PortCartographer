# PortCartographer.sh
rip of C4l1b4n work with some additions 


## Description
This Bash script automates port scans and enumerates basic services.
C4l1b4n wrote this "automator" because he found some in python, but he was searching for one written in bash. Moreover, he aimed to improve my skills in bash (don't we all).
It can be used in CTFs like Vulnhub or HackTheBox and also in other penetration testing environments like OSCP.

First, this script performs a quick nmap SYN-TCP scan (all ports) and then a deep one (open ports previously discovered) plus a UDP scan on top ports.
Multiple NSE scripts are run on most important services.
Secondly, it runs multiple modules on TCP ports 80,139,389,443 and/or 445 if they are found open.
All these scans are saved into files, quick-scan's result is printed as console's output.

After the first scan, the remaining are done in parallel by default; otherwise you can specify a step-by-step scan, where they will be performed sequentially.


## New Version Update (26/04/2024)
New version of the tool released with new banner, modules, configurations and expanded code.
Renamed to Tricorder as fairscan did not want my insane edits/mods. 


## Usage
switches must be listed first
```
Usage:    ./PortCartographer.sh [-h] [-s] [-f] -w [WORDLIST] -H [hostname] -o [Windows|Linux] target_ip target_name"
         target_ip        Ip address of the target
         target_name        Target name, a directory will be created using this path
Options: -w wordlist        Specify a wordlist for gobuster. (The default one is big.txt from dirb's lists)
         -H hostname    Specify hostname (fqdn). MUST BE IN QUOTES (add it to /etc/hosts)
         -h                Show this helper
         -s                Step-by-step: nmap scans are done first, then service port scans not in parallel, one by one.
         -f                Force-scans. It doesn't perform ping to check if the host is alive.
         -o Windows|Linux  Force-scans with entered os which should be case sensitive Linux/Windows.
```

## Examples
```
$ ./PortCartographer.sh 10.10.10.10 kioptrix1
$ ./PortCartographer.sh -s 10.10.10.10 kioptrix2
$ ./PortCartographer.sh -s -w /usr/share/wordlists/dirb/common.txt 10.10.10.10 kioptrix3
$ ./PortCartographer.sh -f -H kioptrix4.com 10.10.10.10 kioptrix4
$ ./PortCartographer.sh -h
```
https://raw.githubusercontent.com/chromefinch/PortCartographer/master/demo.png

## Requirements
```
ping
nmap
gobuster
nikto
curl
enum4linux
whatweb
hakrawler
wget
```

## Supported modules (old and new)
Generals:
- OS detection through ping. (a little flaky so if you know the OS beforehand, using the -o switch is better)
- Quick SYN-TCP nmap's scan, all ports.
- Deep SYN-TCP nmap's scan on discovered open ports.
- NSE namp's scan through selected scripts on most important services. No bruteforcing or autopwn scripts are on the list. 
- UDP nmap's scan on TOP N ports, choosen by you in the configurations.

HTTP and HTTPS (if any/tcp outside of 443,22,445,21,139,135,139,3398 or 443/tcp are discovered open): 
- Nikto's scan.
- Gobuster's dir scan, with different wordlists based on OS discovered.
- Gobuster's vhost scan, if "hostname" parameter is specified.
- Robots.txt download, if present, through curl.
- Whatweb's scan.
- HTTP-Verbs enumeration, through curl, based on gobuster's dir scan results.

SMB & co (if 139/tcp ,389/tcp or 445/tcp are discovered open):
- Enum4linux's scan.

FTP mirror (if 21/tcp is discovered): 
- wget -m ftp://anonymous@hostname:21


## Configurations
Configurations can be easily found at the top lines of the script. You can modify values with your preferences.
Here is an example of the configurations I'm currently using:
```
### NMAP
# minimum rate for the quickest scan
nmap_min_rate="5000"
# top udp ports to scan
nmap_top_udp="100"


### NIKTO
# maximum time length for the scan
nikto_maxtime="10m"


### GOBUSTER
## Linux
# directory bruteforce wordlist for detected linux machines
gobuster_dir_linux_wordlist="/opt/SecLists/Discovery/Web-Content/raft-small-words.txt"
# directory bruteforce extensions for detected linux machines
gobuster_dir_linux_extensions="php,html,txt"


## Windows
# directory bruteforce wordlist for detected windows machines
gobuster_dir_windows_wordlist="/opt/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt"
# directory bruteforce extensions for detected windows machines
gobuster_dir_windows_extensions="php,html,asp,aspx,jsp"


## Unknown OS
# directory bruteforce wordlist for NOT detected OS
gobuster_dir_unknown_wordlist="/opt/SecLists/Discovery/Web-Content/raft-small-words.txt"
# directory bruteforce extensions for NOT detected OS
gobuster_dir_unknown_extensions="php,html,txt,asp,aspx,jsp"


## All OSs
# vhost bruteforce wordlist
gobuster_vhost_wordlist="/opt/SecLists/Discovery/DNS/combined_subdomains.txt"
# number of threads
gobuster_threads="100"


### WHATWEB
# aggression level
whatweb_level="3"
```

If you want to quickly check your current configurations you can use this command:
```
head -n 54 ~/PortCartographer.sh | tail -n 48
```


## Results
A directory with target_name as path/name will be created.
Inside it, a note_$name.txt file will be created, where you can write your notes, plus another directory, named /Scans.
Inside /Scans , output files will be stored in different folders.

## Notes
C4l1b4n wrote this script to automate his enumeration, therefore it performs only what he used to running during his CTFs.
I moded it because I have no sense. 

## License
This project is licensed under MIT License - see the LICENSE.md file for details.
