# oscp-cheatsheet
This repository describes cheat sheet and knowledge for OSCP.

# Contents

# Enumeration
## Host
### nmap
### Example
```console
nmap -sV -T4 -Pn <Target IP Address>
```
#### Options
`-sV`: Show opening ports and running services.  
`-T4`: Prohibit the dynamic scan delay from exceeding 10ms for TCP ports  
`-Pn`: Disable sending ping packets to discover a host  
`-A`: Detect OS and its version.  
`-p`: Specify range of ports. Scan all ports (1-65535) if use the option `-p-`  

# Linux command
## String Processing
### Remove white spaces
```
sed 's/ //g'
```

# LICENSE
MIT

