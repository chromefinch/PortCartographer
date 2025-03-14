#!/usr/bin/env bash

##                        ##
##   Written by C4l1b4n   ##
##  Mod'd by chromefinch  ##
##                        ##

#----------------------------------------------------------------------------------------------------------------------
##### CONFIGURATIONS - CHANGE THEM #####
#----------------------------------------------------------------------------------------------------------------------
### NMAP
# minimum rate for the quickest scan
nmap_min_rate="5000"
# top udp ports to scan
nmap_top_udp="100"


### NIKTO
# maximum time length for the scan
nikto_maxtime="3m"


### GOBUSTER
## Linux
# directory bruteforce wordlist for detected linux machines
feroxbuster_dir_linux_wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
# directory bruteforce extensions for detected linux machines
feroxbuster_dir_linux_extensions="php,html,txt,pdf"

## Windows
# directory bruteforce wordlist for detected windows machines
feroxbuster_dir_windows_wordlist="/usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt"
# directory bruteforce extensions for detected windows machines
feroxbuster_dir_windows_extensions="php,html,asp,aspx,jsp,pdf,wsdl"

## Unknown OS
# directory bruteforce wordlist for NOT detected OS
feroxbuster_dir_unknown_wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
# directory bruteforce extensions for NOT detected OS
feroxbuster_dir_unknown_extensions="php,html,txt,asp,aspx,jsp,pdf,wsdl,asmx"

## All OSs
# vhost bruteforce wordlist
gobuster_vhost_wordlist="/usr/share/seclists/Discovery/DNS/combined_subdomains.txt"
# number of threads
gobuster_threads="100"


### WHATWEB
# aggression level
whatweb_level="3"

# Spinning characters
sp='|/-\\'

#----------------------------------------------------------------------------------------------------------------------
##### CONFIGURATIONS' END #####
#----------------------------------------------------------------------------------------------------------------------



# NSE's scripts run by nmap
nse="dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-recursion,dns-service-discovery,dns-srv-enum,fcrdns,ftp-anon,ftp-bounce,ftp-libopie,ftp-syst,ftp-vuln-cve2010-4221,http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-backup-finder,http-bigip-cookie,http-cakephp-version,http-config-backup,http-cookie-flags,http-devframework,http-exif-spider,http-favicon,http-frontpage-login,http-generator,http-git,http-headers,http-hp-ilo-info,http-iis-webdav-vuln,http-internal-ip-disclosure,http-jsonp-detection,http-mcmp,http-ntlm-info,http-passwd,http-php-version,http-qnap-nas-info,http-sap-netweaver-leak,http-security-headers,http-server-header,http-svn-info,http-trane-info,http-userdir-enum,http-vlcstreamer-ls,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-2129,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-cve2017-1001000,http-vuln-misfortune-cookie,http-webdav-scan,http-wordpress-enum,http-wordpress-users,https-redirect,imap-capabilities,imap-ntlm-info,ip-https-discover,membase-http-info,msrpc-enum,mysql-audit,mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables,mysql-vuln-cve2012-2122,nfs-ls,nfs-showmount,nfs-statfs,pop3-capabilities,pop3-ntlm-info,pptp-version,rdp-ntlm-info,rdp-vuln-ms12-020,realvnc-auth-bypass,riak-http-info,rmi-vuln-classloader,rpc-grind,rpcinfo,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-print-text,smb-protocols,smb-security-mode,smb-vuln-cve-2017-7494,smb-vuln-ms10-061,smb-vuln-ms17-010,smb2-capabilities,smb2-security-mode,smb2-vuln-uptime,smtp-commands,smtp-ntlm-info,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,ssh-auth-methods,sshv1,ssl-ccs-injection,ssl-cert,ssl-heartbleed,ssl-poodle,sslv2-drown,sslv2,telnet-encryption,telnet-ntlm-info,tftp-enum,unusual-port,vnc-info,vnc-title"

version="1.4.7"
stepbystep="0"
force="0"
os=''
hostname=''
gobuster_wordlist=''
gobuster_extensions=''
userid=$SUDO_USER
folder=$(pwd)

#usage helper
usage () {
	echo ""
	echo "Usage:    ./PortCartographer.sh [-h] [-s] [-f] -w [wordlist] -H [hostname] -o [Windows|Linux] target_ip target_name"
	echo ""
	echo "          target_ip         IP address of the target"
	echo "          target_name       Target name, a directory will be created using this path"
	echo "Options:  -w wordlist       Specify a wordlist (absolute path) for gobuster. (The default one is big.txt from dirb's lists)"
	echo "          -H hostname       Specify hostname (fqdn). (add it to /etc/hosts)"
	echo "          -h                Show this helper"
	echo "          -s                Step-by-step: nmap scans are done first, then service port scans not in parallel, one by one."
	echo "          -f                Force-scans. It doesn't perform ping to check if the host is alive."
	echo "          -o Windows|Linux  Force-scans with entered os which should be case sensitive Linux/Windows."
	exit
}

banner () {
	title='
 ______                  _______                                                _
(_____ \             _  (_______)              _                               | |
 _____) )__   ____ _| |_ _       _____  ____ _| |_ ___   ____  ____ _____ ____ | |__  _____  ____
|  ____/ _ \ / ___|_   _) |     (____ |/ ___|_   _) _ \ / _  |/ ___|____ |  _ \|  _ \| ___ |/ ___)
| |   | |_| | |     | |_| |_____/ ___ | |     | || |_| ( (_| | |   / ___ | |_| | | | | ____| |
|_|    \___/|_|      \__)\______)_____|_|      \__)___/ \___ |_|   \_____|  __/|_| |_|_____)_|
                                                       (_____|           |_|
'
	print_purple "$title"
	echo "	[*] PortCartographer, script for automated enumeration [*]"
	echo ""
	echo "	CODER:		C4l1b4n"
	echo "	MODDER:		chromefinch"
	echo "	VERSION:	$version"
	echo "	GITHUB:		https://github.com/chromefinch/PortCartographer"
	echo ""
}

#----------------------------------------------------------------------------------------------------------------------
##### SET ENV #####
#----------------------------------------------------------------------------------------------------------------------

#check correct order of parameters and assign $ip and $name
check_parameters () {
	while getopts "w:hH:s:o:f" flag; do
	case "${flag}" in
		H) hostname=$OPTARG;
			print_green "Domain $hostname found";;
		w) temp_wordlist=$OPTARG;;
		h) usage
			exit;;
		s) stepbystep="1";;
		o) os=$OPTARG;
			force="1";;
		f) force="1";;
		*) print_red "Wrong parameters, use -h to show the helper"
			exit;;
	esac
	done
	if [ $(( $# - $OPTIND )) -lt 1 ] ; then
		print_red "Wrong parameters, use -h to show the helper"
		exit
	fi
	ip=${@:$OPTIND:1}
	name=${@:$OPTIND+1:1}
}
#check the correct format of the ip address
check_ip () {
	check_ip=$(echo "$ip" | tr '.' '\n')
	counter=0
	for part in $check_ip
	do
		counter=`expr $counter + 1`
		if [[ $part = *[!0-9]* ]] || [[ $part -gt 255 ]] ; then
			print_red "[**] Wrong IP"
		fi
	done
	if [[ counter -ne 4 ]] ; then
			hostname="$ip"
			ip="$(nslookup $hostname | grep -E "Address\: \S+" | sed "s/Address: //g")"
			force="1"
			print_red "Attempting Error recovery with the following assumed:"
			echo -H $hostname $ip $name
			check_dir
	fi
}
#check if the $name path already exists
check_dir () {
	if [[ -d "$name" ]] ; then
		print_red "[**] $name directory already exists!" 1>&2
    		exit 1
	fi
	if [[ $EUID -ne 0 ]]; then
		print_red "This script must be run as root"
			exit 1
	fi
}
#check if the wordlists specified exist
check_w () {
	if [[ -n "$feroxbuster_dir_linux_wordlist" ]] && ! [[ -f "$feroxbuster_dir_linux_wordlist" ]] ; then
		print_red "[**] Wordlist $feroxbuster_dir_linux_wordlist doesn't exist, fix the configurations! " 1>&2
    		exit 1
	fi
	if [[ -n "$feroxbuster_dir_windows_wordlist" ]] && ! [[ -f "$feroxbuster_dir_windows_wordlist" ]] ; then
		print_red "[**] Wordlist $feroxbuster_dir_windows_wordlist doesn't exist, fix the configurations! " 1>&2
    		exit 1
	fi
	if [[ -n "$feroxbuster_dir_unknown_wordlist" ]] && ! [[ -f "$feroxbuster_dir_unknown_wordlist" ]] ; then
		print_red "[**] Wordlist $feroxbuster_dir_unknown_wordlist doesn't exist, fix the configurations! " 1>&2
    		exit 1
	fi
	if [[ -n "$gobuster_vhost_wordlist" ]] && ! [[ -f "$gobuster_vhost_wordlist" ]] ; then
		print_red "[**] Wordlist $gobuster_vhost_wordlist doesn't exist, fix the configurations! " 1>&2
    		exit 1
	fi
	if [[ -n "$temp_wordlist" ]] && ! [[ -f "$temp_wordlist" ]] ; then
		print_red "[**] Wordlist $temp_wordlist doesn't exist! " 1>&2
    		exit 1
	fi
}
#check if hostname is set in /etc/hosts
check_hostname () {
	if [[ -n "$hostname" ]] ; then
		temp_hostname=$(cat /etc/hosts | grep -E "(\s)+$hostname+(\s|$)")
		if [[ -z "$temp_hostname" ]] ; then
			print_red "You specified $hostname as hostname, but you didn't put it in /etc/hosts ! I've added $ip $hostname, but pls remove later!"
			sudo echo "$ip $hostname" >> /etc/hosts
		fi
	else
		hostname=$ip
	fi
}

#check if the host is alive
host_alive () {
	if [[ $force -ne "1" ]] ; then
		test_host=$(ping $ip -c 1 -W 3 | grep "ttl=" | awk -F 'ttl=' '{print $2}' | cut -d' ' -f1)
		if test -z "$test_host" ; then
			print_red "[**] Oops, the target doesn't seem alive! Use -f to override" 1>&2
			exit 1
		else
			case "${test_host}" in
				6[34]) os="Linux";;
				12[78]) os="Windows";;
				25[45]) os="AIX/Cisco/FreeBSD/HP-UX/Irix/NetBSD/OpenBSD/Solaris";;
				*) os='';;
			esac
		fi
	fi
}
#set the environment
set_env () {
	mkdir $name
	folder=$folder/$name
	cd $name
	sudo chown 2771 .
	> note_$name.txt
	mkdir "Scans"
    mkdir "tmp"
	cd "Scans"
	sudo chown -R $userid:$userid $folder
}

# Array to store function names and PIDs
declare -A processes

display_table() {
    local table_start_line=$(tput lines)
    local table_start_line=$((table_start_line-7))
    printf "\033[$table_start_line;0H%-20s %-10s %-20s\n" "Function" "PID" "Status"
    let table_start_line++
    for function_name in "${!processes[@]}"; do
        pid=${processes[$function_name]}
        if kill -0 "$pid" 2> /dev/null; then
        status=$(cat "$folder/tmp/$function_name.tmp")
        else
        status=$(echo -n "Ended " && cat "$folder/tmp/$function_name.tmp")
        fi
        printf "\033[$table_start_line;0H%-20s %-10s %-20s\n" "$function_name" "$pid" "$status"
        let table_start_line++
    done
}

# Continuously update and display the table
activity() {
    while true; do
        display_table
        sleep 1
        # Check if all processes have finished
        all_finished=true
        for pid in "${processes[@]}"; do
            echo "PID $pid: ${processes[$pid]}" >> $folder/tmp/debug.log
            if kill -0 "$pid" 2> /dev/null; then
                all_finished=false
                break
            fi
        done
        if $all_finished; then
            display_table
            unset processes[*]
            print_purple "[*] Continuing..."
            break
        fi
    done
}
#----------------------------------------------------------------------------------------------------------------------
##### NMAP SCANS #####
#----------------------------------------------------------------------------------------------------------------------

#nmap quick scan
quick_nmap () {
	if test -z $os ; then
		os="Unknown"
	fi

	if test $os == "Windows" ; then
		gobuster_wordlist=$feroxbuster_dir_windows_wordlist
		gobuster_extensions=$feroxbuster_dir_windows_extensions
	elif test $os == "Unknown" ; then
		gobuster_wordlist=$feroxbuster_dir_unknown_wordlist
		gobuster_extensions=$feroxbuster_dir_unknown_extensions
	else
		gobuster_wordlist=$feroxbuster_dir_linux_wordlist
		gobuster_extensions=$feroxbuster_dir_linux_extensions
	fi

	if [[ -n "$temp_wordlist" ]] ; then
		gobuster_wordlist=$temp_wordlist
	fi
	banner
	echo ""
	echo "TARGET ADDRESS:	$hostname"
	echo "TARGET OS:	$os"
	echo ""
	if [ -z "$quickPorts" ] ; then
        portzdefault="--top-ports 10000"
        read -p "Enter desired ports to quick scan (input is expecting nmap flag example -p443) default: [$portzdefault]:" portsv
        quickPorts=${portsv:-$portzdefault}
	fi
 	check=$(nmap -sS $quickPorts -n -Pn $ip | grep "/tcp")
	if [[ -z $check ]] ; then
		print_red "[**] The target doesn't have any open ports... check manually!"
		cd ..
		cd ..
		rm -r $name
		exit
	else
        echo ""
		echo "PORT   STATE  SERVICE" #> quickNmap_$name.txt
		echo "$check" #>> quickNmap_$name.txt
		#cat quickNmap_$name.txtf
		echo " "
		mkdir nmap
	fi
}
#nmap deep scan
slow_nmap() {
  ports=$(echo "$check" | grep "/tcp" | cut -d ' ' -f1 | cut -d '/' -f1 | tr '\n' ',' | rev | cut -c 2- | rev)
  print_yellow "[+] Running deep Nmap scan on ports: $ports..."

  # Start the nmap scan in the background
  nmap -sS -A -p $ports $ip > nmap/deepNmap_$name.txt &
  slow_nmap_pid=$!
  
  # Display PID and initial progress message
  printf "Deep Nmap scan PID: $slow_nmap_pid "

  # Wait for the process to finish and update progress
  while kill -0 $slow_nmap_pid 2> /dev/null; do
    printf "\b${sp:i++%${#sp}:1}"
    sleep 0.1
  done

  # Clear the progress line
  printf "\r\033[K"

  # Print the final message
  print_green "[-] Deep Nmap scan done!"
}

#nmap NSE scan
nse_nmap () {
	print_yellow "[+] Running NSE Nmap scan..."
	ports=$(echo "$check" | grep " open " | cut -d ' ' -f1 | cut -d '/' -f1 | tr '\n' ',' | rev | cut -c 2- | rev)
	nmap -sV -n -O --script "$nse" -p $ports $ip > nmap/nse_$name.txt&
    nse_nmap_pid=$!
    # Display PID and initial progress message
    printf "NSE Nmap scan PID: $nse_nmap_pid "
    # Wait for the process to finish and update progress
    while kill -0 $nse_nmap_pid 2> /dev/null; do
        printf "\b${sp:i++%${#sp}:1}"
        sleep 0.1
    done
    # Clear the progress line
    printf "\r\033[K"
    # Print the final message
	print_green "[-] NSE Nmap scan done!"
}

#nmap UDP scan
udp_nmap () {
	print_yellow "[+] Running UDP Nmap scan on $nmap_top_udp common ports..." 
	nmap -sU --top-ports $nmap_top_udp --version-all $ip > nmap/udpNmap_$name.txt
    # Print the final message
	print_green "[-] UDP Nmap scan done for $nmap_top_udp common ports!"
}
#----------------------------------------------------------------------------------------------------------------------
##### SERVICES SCANS #####
#----------------------------------------------------------------------------------------------------------------------

#nikto scan, $1 --> protocol, $2 --> port
nikto_scan () {
	print_yellow "[+] Running Nikto on port $2..." > $folder/tmp/nikto\ scan.tmp
	nikto -port $2 -host $hostname -maxtime $nikto_maxtime -ask no 2> /dev/null >> $1/nikto_$2_$name.txt
    # Print the final message
	temp=$(cat $1/nikto_$2_$name.txt | grep "+ 0 host(s) tested")
	if [[ -z $temp ]] ; then
	print_green "[-] Nikto on port $2 done!" > $folder/tmp/nikto\ scan.tmp
	else
		sudo rm $1/nikto_$2_$name.txt 2>/dev/null
	print_red "[-] nikto_scan on $2 empty, deleted" > $folder/tmp/nikto\ scan.tmp
	fi
}

#feroxbuster scan, $1 --> protocol, $2 --> port
feroxbuster_dir () {
	print_yellow "[+] Running feroxbuster on port $2..." > $folder/tmp/feroxbuster_dir\ scan.tmp
	feroxbuster -u $1://$hostname:$2 -w $gobuster_wordlist -x $gobuster_extensions -t $gobuster_threads -k --dont-scan '/(js|css|images|img|icons)' --filter-status 404 --extract-links --scan-dir-listings -q > $1/feroxbuster_dir_$2_$name.txt 2> /dev/null
	sed -i '/Auto-filtering found 404-like response and created new filter/d' $1/feroxbuster_dir_$2_$name.txt 2> /dev/null
	sed -i '/^$/d' $1/feroxbuster_dir_$2_$name.txt 2> /dev/null
	if grep -q 'skipping...$' $1/feroxbuster_dir_$2_$name.txt; then
  		rm $1/feroxbuster_dir_$2_$name.txt
		touch $1/feroxbuster_dir_$2_$name.txt
  	fi
# Print the final message
	if ! [ -s $1/feroxbuster_dir_$2_$name.txt ] ; then
		rm $1/feroxbuster_dir_$2_$name.txt
		print_red "[-] feroxbuster on port $2 found nothing!               " > $folder/tmp/feroxbuster_dir\ scan.tmp
	else
		print_green "[-] feroxbuster on port $2 done!               " > $folder/tmp/feroxbuster_dir\ scan.tmp
	fi
}
#feroxbuster redirect scan, $1 --> protocol, $2 --> port
feroxbuster_redir () {
	print_yellow "[+] feroxbuster scaning redirects..." 
 	if ! [ -s $1/feroxbuster_dir_$2_$name.txt ] ; then
		print_red "[-] $1/feroxbuster_dir_$2_$name.txt was empty, skipping"
	else
	redirects=$(cat $1/feroxbuster_dir_$2_$name.txt | grep -E '3..      GET' | awk '{print $NF}')
	for r in $redirects ; do
		fix+=$(echo "$r " | sed 's/127.0.0.1/'$hostname'/; s/localhost/'$hostname'/') 2> /dev/null
	done
	fixed+=$(echo $fix | xargs -n1 |sort -u)
 	c=0
 	for f in $fixed; do
  		c=$((c + 1))
		feroxbuster -u $f -w $gobuster_wordlist -x $gobuster_extensions -t $gobuster_threads -k --filter-status 404 --extract-links --scan-dir-listings -q > $1/feroxbuster_redir_$2_$c.txt 2> /dev/null&
		feroxbuster_redir_pid=$!
		# Display PID and initial progress message
		printf "feroxbuster redirect scaning for $f with pid: $feroxbuster_redir_pid "
		# Wait for the process to finish and update progress
		while kill -0 $feroxbuster_redir_pid 2> /dev/null; do
		printf "\b${sp:i++%${#sp}:1}"
		sleep 0.1
		done
		# Clear the progress line
		printf "\r\033[K"
	if grep -q 'skipping...$' $1/feroxbuster_redir_$2_$c.txt; then
		rm $1/feroxbuster_redir_$2_$c.txt
  	else
   		cat $1/feroxbuster_redir_$2_$c.txt >> $1/feroxbuster_redir_$2_$name.txt
     		rm $1/feroxbuster_redir_$2_$c.txt
  	fi
  	done

	sed -i '/Auto-filtering found 404-like response and created new filter/d' $1/feroxbuster_redir_$2_$name.txt 2> /dev/null
	sed -i '/^$/d' $1/feroxbuster_redir_$2_$name.txt 2> /dev/null

	cat $1/feroxbuster_redir_$2_$name.txt >> $1/feroxbuster_dir_$2_$name.txt  2> /dev/null
# Print the final message
	if ! [ -s $1/feroxbuster_redir_$2_$name.txt ] ; then
		rm $1/feroxbuster_redir_$2_$name.txt
		print_red "[-] feroxbuster on port $2 found no redirects!"
	else
		print_green "[-] feroxbuster redirect scan on port $2 done!"
	fi
# start verb enumn
	if ! [ -e $1/feroxbuster_dir_$2_$name.txt ] ; then
		print_red "[-] Unable to enumerate, $1/feroxbuster_dir_$2_$name.txt is blank, skipping"
	else
        print_yellow "[+] Enumerating http-verbs from feroxbuster results on port $2..."
        not_redirected=$(cat $1/feroxbuster_dir_$2_$name.txt | grep -E '200      GET|401      GET' | awk '{print $NF}')
        redirected=$(cat $1/feroxbuster_dir_$2_$name.txt | grep -E '3..      GET' | awk '{print $NF}')
        for i in $not_redirected ; do
           concatenation+="$not_redirected "
        done
        for r in $redirected ; do
           concatenation+=$(echo "$r " | sed 's/127.0.0.1/'$hostname'/; s/localhost/'$hostname'/')
        done
        scan+=$(echo $concatenation | xargs -n1 |sort -u)
        for i in $scan; do
            verb_result=$(curl -sSikI -X OPTIONS "$i" | grep -w -E 'HTTP|Allow:' | sed "s|HTTP/1.1 404 Not Found||g")
            test=${#verb_result}
            if [[ $test > "1" ]] ; then
                echo $i >> $1/$1-verbs.txt
                echo $verb_result >> $1/$1-verbs.txt
                echo "---" >> $1/$1-verbs.txt
            fi
        done
        print_green "[-] Enumeration http-verbs on port $2 done!"
    fi
    fi
}
#gobuster vhost scan, $1 --> protocol, $2 --> port
gobuster_vhost () {
	if test $hostname != $ip ; then
		print_yellow "[+] Running gobuster vhost on port $2..." > $folder/tmp/gobuster_vhost\ scan.tmp
		gobuster vhost -u $1://$hostname:$2 -w $gobuster_vhost_wordlist -t $gobuster_threads -q -k --append-domain --output $1/gobuster_subdomains_$2_$name.txt >/dev/null 2>&1
    gobuster_vhost_pid=$!

    # Print the final message
		if ! [ -s $1/gobuster_subdomains_$2_$name.txt ] ; then
			rm $1/gobuster_subdomains_$2_$name.txt
			print_red "[-] Gobuster vhost on port $2 found nothing!" > $folder/tmp/gobuster_vhost\ scan.tmp
		else
			print_green "[-] Gobuster vhost on port $2 done!" > $folder/tmp/gobuster_vhost\ scan.tmp
		fi
	fi
}
#hakrawler scan, $1 --> protocol, $2 --> port
hakrawler_crawl () {
	print_yellow "[+] Running hakrawler on "$1://$hostname:$2"..." > $folder/tmp/hakrawler\ scan.tmp
	echo "$1://$hostname:$2" | hakrawler -insecure -d 0 -u -timeout 5 | sort -u -o $1/hakrawler$2_$name.txt >/dev/null 2>&1
   # Print the final message
	if ! [ -s $1/hakrawler$2_$name.txt ] ; then
		rm $1/hakrawler$2_$name.txt
		print_red "[-] hakrawler for $1://$hostname:$2 found nothing!" > $folder/tmp/hakrawler\ scan.tmp
	else
		print_green "[-] hakrawler for $1://$hostname on port $2 done!" > $folder/tmp/hakrawler\ scan.tmp
	fi
}


#download robots.txt, $1 --> protocol, $2 --> port
robots_txt () {
	print_yellow "[+] Searching robots.txt on port $2..." > $folder/tmp/robots\ scan.tmp
	robot_=$(curl -sSik -m 3 "$1://$hostname:$2/robots.txt" >/dev/null 2>&1) 
	if [ $? = 0 ]; then
	temp=$(echo $robot_ | grep "404")
		if [[ -z $temp ]] ; then
			echo "$robot_" >> $1/robotsTxt_$2_$name.txt
			print_green "[-] Robots.txt on port $2 FOUND!" > $folder/tmp/robots\ scan.tmp
		else
			print_red "[-] Robots.txt on port $2 NOT found." > $folder/tmp/robots\ scan.tmp
		fi
	else
	print_red "[-] Robots.txt on port $2 NOT found." > $folder/tmp/robots\ scan.tmp
	fi
}

# whatweb scan, $1 --> protocol, $2 --> port
whatweb_scan () {
	print_yellow "[+] Running whatweb on $1://$ip:$2..." > $folder/tmp/whatweb\ scan.tmp
	whatweb $1://$ip:$2 -a $whatweb_level -v --color never --no-error 2>/dev/null >> $1/whatweb_$2_$name.txt
	print_green "[-] Whatweb on $1://$ip:$2 done!" > $folder/tmp/whatweb\ scan.tmp
	print_yellow "[+] Running whatweb on $1://$hostname:$2..." > $folder/tmp/whatweb\ scan.tmp
	whatweb $1://$hostname:$2 -a $whatweb_level -v --color never --no-error 2>/dev/null >> $1/whatweb_$2_$name.txt
	print_green "[-] Whatweb on $1://$hostname:$2 done!" > $folder/tmp/whatweb\ scan.tmp
	if [[ $(du $1/whatweb_$2_$name.txt | awk '{print $1}') > 1 ]] ; then
		print_green "[-] Whatweb done & $1/whatweb_$2_$name.txt has contents!" > $folder/tmp/whatweb\ scan.tmp
	else
		sudo rm $1/whatweb_$2_$name.txt 2>/dev/null
		print_red "[-] Whatweb done & $1/whatweb_$2_$name.txt is empty, deleted" > $folder/tmp/whatweb\ scan.tmp
	fi
}
#run enum4linux if ports 139,389 or 445 are open
check_smb() {
	temp_smb=$(echo "$check" | grep -w -E '139/tcp|389/tcp|445/tcp')
	if [[ -n $temp_smb ]] ; then
		print_yellow "[+] Running enum4linux..."
		mkdir smb
		enum4linux -a -M -l -d $ip 2> /dev/null >> smb/enum4linux_$name.txt
		print_green "[-] Enum4linux done!"
	fi
}
clone_ftp() {
	temp_ftp=$(echo "$check" | grep -w -E '21/tcp')
	if [[ -n $temp_ftp ]] ; then
		print_yellow "[+] Running ftp mirror..."
		mkdir ftp
		cd ftp
		wget -m ftp://anonymous@$ip:21 2> /dev/null
		cd ..
		print_green "[-] ftp mirror done!"
	fi
}
clean(){
echo done
}
#----------------------------------------------------------------------------------------------------------------------
##### UTILITIES #####
#----------------------------------------------------------------------------------------------------------------------
print_green (){
	echo -e "\033[0;32m$1\033[0m"
}
print_yellow (){
	echo -e "\033[0;33m$1\033[0m"
}
print_red (){
	echo -e "\033[0;31m$1\033[0m"
}
print_blue (){
	echo -e "\033[0;34m$1\033[0m"
}
print_purple (){
	echo -e "\033[0;35m$1\033[0m"
}

#----------------------------------------------------------------------------------------------------------------------
##### MAIN #####
#----------------------------------------------------------------------------------------------------------------------

#check if port http is open
check_port_80 () {
	temp_80=$(echo "$check" | grep -v -we "443/tcp" -we '22/tcp' -we '445/tcp' -we '21/tcp' -we '139/tcp' -we '135/tcp' -we '3389/tcp')
	if [[ -n $temp_80 ]] ; then
	portz=$(echo "$temp_80" | grep "/tcp" | cut -d ' ' -f1 | cut -d '/' -f1  | rev | cut -c 1- | rev)
	mkdir http
 	print_yellow "[+] Starting web scans..."
	if [[ $busterAnswer == "dir" ]] ; then
		for i in ${portz[@]}; do
			hakrawler_crawl "http" $i &
			processes["hakrawler scan"]="$!"
			nikto_scan "http" $i &
			processes["nikto scan"]="$!"
			robots_txt "http" $i &
			processes["robots scan"]="$!"
			whatweb_scan "http" $i &
			processes["whatweb scan"]="$!"
			#gobuster_vhost "http" $i
			feroxbuster_dir "http" $i &
			processes["feroxbuster_dir scan"]="$!"
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			activity
			unset processes[*]
			feroxbuster_redir "http" $i
			#add more scans on port 80!
		done
  		print_green "[-] http web scans complete"
	fi
	if [[ $busterAnswer == "vhost" ]] ; then
		for i in ${portz[@]}; do
			hakrawler_crawl "http" $i &
			processes["hakrawler scan"]="$!"
			nikto_scan "http" $i &
			processes["nikto scan"]="$!"
			robots_txt "http" $i &
			processes["robots scan"]="$!"
			whatweb_scan "http" $i &
			processes["whatweb scan"]="$!"
			gobuster_vhost "http" $i &
			processes["gobuster_vhost scan"]="$!"
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			activity
			unset processes[*]
			#feroxbuster_dir "http" $i
			#add more scans on port 80!
		done
  		print_green "[-] http web scans complete"
	fi
	if [[ $busterAnswer == "all" ]] ; then
		for i in ${portz[@]}; do
			hakrawler_crawl "http" $i &
			processes["hakrawler scan"]="$!"
			nikto_scan "http" $i &
			processes["nikto scan"]="$!"
			robots_txt "http" $i &
			processes["robots scan"]="$!"
			whatweb_scan "http" $i &
			processes["whatweb scan"]="$!"
			gobuster_vhost "http" $i &
			processes["gobuster_vhost scan"]="$!"
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			activity
			unset processes[*]
			feroxbuster_dir "http" $i &
			processes["feroxbuster_dir scan"]="$!"
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			activity
			unset processes[*]
			feroxbuster_redir "http" $i
			#add more scans on port 80!
		done
  		print_green "[-] http web scans complete"
	fi
	if [[ $busterAnswer == "N" ]] ; then
		for i in ${portz[@]}; do
			hakrawler_crawl "http" $i &
			processes["hakrawler scan"]="$!"
			nikto_scan "http" $i &
			processes["nikto scan"]="$!"
			robots_txt "http" $i &
			processes["robots scan"]="$!"
			whatweb_scan "http" $i &
			processes["whatweb scan"]="$!"
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			activity
			unset processes[*]
			#gobuster_vhost "http" $i
			#feroxbuster_dir "http" $i
			#http_verbs "http" $i 
			#add more scans on port 80!
		done
  		print_green "[-] http web scans complete"
	fi
	if [[ -z $busterAnswer ]] ; then
		for i in ${portz[@]}; do
			hakrawler_crawl "http" $i &
			processes["hakrawler scan"]="$!"
			nikto_scan "http" $i &
			processes["nikto scan"]="$!"
			robots_txt "http" $i &
			processes["robots scan"]="$!"
			whatweb_scan "http" $i &
			processes["whatweb scan"]="$!"
			#gobuster_vhost "http" $i
			feroxbuster_dir "http" $i &
			processes["feroxbuster_dir scan"]="$!"
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			activity
			unset processes[*]
			feroxbuster_redir "http" $i
			#add more scans on port 80!
		done
  		print_green "[-] http web scans complete"
	fi
	fi
}

#check if port 443 is open
check_port_443 () {
	temp_443=$(echo "$check" | grep -w "443/tcp")
	if [[ -n $temp_443 ]] ; then
		mkdir https
  		print_yellow "[+] Starting https web scans..."
		if [[ -z $busterAnswer ]] ; then
			hakrawler_crawl "https" "443" &
			processes["hakrawler scan"]="$!"
			nikto_scan "https" "443" &
			processes["nikto scan"]="$!"
			robots_txt "https" "443" &
			processes["robots scan"]="$!"
			whatweb_scan "https" "443" &
			processes["whatweb scan"]="$!"
			#gobuster_vhost "https" "443"
			feroxbuster_dir "https" "443" &
			processes["feroxbuster_dir scan"]="$!"
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			activity
			feroxbuster_redir "https" "443"
			#add more scans on port 443!
   			print_green "[-] https web scans complete"
		fi
		if [[ $busterAnswer == "N" ]] ; then
			hakrawler_crawl "https" "443" &
			processes["hakrawler scan"]="$!"
			nikto_scan "https" "443" &
			processes["nikto scan"]="$!"
			robots_txt "https" "443" &
			processes["robots scan"]="$!"
			whatweb_scan "https" "443" &
			processes["whatweb scan"]="$!"
			#gobuster_vhost "https" "443"
			#feroxbuster_dir "https" "443"
			#http_verbs "https" "443" &
			#add more scans on port 443!
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			echo ""
			activity
   			print_green "[-] https web scans complete"
		fi
		if [[ $busterAnswer == "all" ]] ; then
			hakrawler_crawl "https" "443" &
			processes["hakrawler scan"]="$!"
			nikto_scan "https" "443" &
			processes["nikto scan"]="$!"
			robots_txt "https" "443" &
			processes["robots scan"]="$!"
			whatweb_scan "https" "443" &
			processes["whatweb scan"]="$!"
			gobuster_vhost "https" "443"&
			processes["gobuster_vhost scan"]="$!"
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                activity
			feroxbuster_dir "https" "443" &
	                processes["feroxbuster_dir scan"]="$!"
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                activity
			feroxbuster_redir "https" "443"
			#add more scans on port 443!
   			print_green "[-] https web scans complete"
		fi
		if [[ $busterAnswer == "vhost" ]] ; then
			hakrawler_crawl "https" "443" &
	                processes["hakrawler scan"]="$!"
			nikto_scan "https" "443" &
	                processes["nikto scan"]="$!"
			robots_txt "https" "443" &
	                processes["robots scan"]="$!"
			whatweb_scan "https" "443" &
	                processes["whatweb scan"]="$!"
			gobuster_vhost "https" "443" &
	                processes["gobuster_vhost scan"]="$!"
			#feroxbuster_dir "https" "443"
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                activity
			feroxbuster_redir "https" "443"
			#add more scans on port 443!
   			print_green "[-] https web scans complete"
		fi
		if [[ $busterAnswer == "dir" ]] ; then
			hakrawler_crawl "https" "443" &
	                processes["hakrawler scan"]="$!"
			nikto_scan "https" "443" &
	                processes["nikto scan"]="$!"
			robots_txt "https" "443" &
	                processes["robots scan"]="$!"
			whatweb_scan "https" "443" &
	                processes["whatweb scan"]="$!"
			#gobuster_vhost "https" "443"
			feroxbuster_dir "https" "443" &
	                processes["feroxbuster_dir scan"]="$!"
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                echo ""
	                activity
			feroxbuster_redir "https" "443"
			#add more scans on port 443!
   			print_green "[-] https web scans complete"
		fi
	fi
}
check_input(){
	check_parameters $@
	check_ip
	check_hostname
	check_dir
	check_w
	host_alive
}
all_scans() {
	if [[ $stepbystep -ne "1" ]] ; then
		quick_nmap
		echo ""
		echo "dir busting is done with feroxbuster while vhost is done with gobuster"
		read -t 15 -p "Do you want to run a dir buster? enter one of the folowing (dir/vhost/all/N) dir is default: " busterAnswer
		echo ""
		slow_nmap
		nse_nmap
        	check_smb 
		clone_ftp 
		check_port_443
  		wait
		check_port_80 
        	udp_nmap &
        	sleep 1
		echo "[+] All scans launched..."
		#add more scans!
	else
		quick_nmap
		echo ""
		echo "dir busting is done with feroxbuster while vhost is done with gobuster"
		read -t 15 -p "Do you want to run a dir buster? enter one of the folowing (dir/vhost/all/N) dir is default: " busterAnswer
		echo ""
		slow_nmap
		nse_nmap
		udp_nmap &
		check_port_80
		wait
		check_port_443
		wait
		check_smb
		clone_ftp
		#add more scans!
	fi
}
#-------------------------- main ------------------------------------
check_input $@ #multiple check on input
set_env #setting working envirnoment
all_scans #do all scans
wait #wait all children
rm -R $folder/tmp
sudo chown -R $userid:$userid $folder
print_purple "[*] All tasks complete!"
