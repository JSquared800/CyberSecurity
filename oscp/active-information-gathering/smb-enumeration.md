# SMB Enumeration

```
nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254 // scans for both of these services
sudo nbtscan -r 10.11.1.0/24
```

We can do OS discovery and enumeration via SMB:

```
┌──(kali㉿kali)-[~]
└─$ nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-22 11:05 CST
...
PORT    STATE SERVICE
139/tcp open  netbios-ssn

Host script results:
| smb-os-discovery: 
|   OS: Windows 2000 (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_2000::-
|   Computer name: jd
|   NetBIOS computer name: JD\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-01-22T19:05:46+02:00
```

Looks good! we can see that this has a possible vulnerability. We can check for vulnerabilities with the command

```
┌──(kali㉿kali)-[~]
└─$ nmap -v -p 139,445 --script smb-vuln-ms08-067 --script-args=unsafe=1 10.11.1.5
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-22 11:11 CST
...
Discovered open port 445/tcp on 10.11.1.5
Discovered open port 139/tcp on 10.11.1.5
...
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx

NSE: Script Post-scanning.
Initiating NSE at 11:11
Completed NSE at 11:11, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.77 seconds
```

4\. Server message block (SMB) is an extremely important service that can be used to determine a wealth of information about a server including its users. Use nmap to identify the lab machines listening on the smb port and then use enum4linux to enumerate those machines. In doing so, you will find a machine with the local user alfred. The flag is located in the comments of one of the SMB shares of the host that has the alfred user.

```
┌──(kali㉿kali)-[~]                                                                                                                                                                                                                        
└─$ nmap -sC -sV -v -p 139,445 192.168.161.6-30
...
┌──(kali㉿kali)-[~]                                                                                                                                                                                                                        
└─$ enum4linux 192.168.161.21
...
OS{REDACTED}
```







