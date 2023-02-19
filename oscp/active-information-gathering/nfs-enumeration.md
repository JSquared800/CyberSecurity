# NFS Enumeration

```
nmap -v -p 111 10.11.1.1-254 // nmap scan for rpcbind
nmap -p 111 --script nfs* 10.11.1.72 // use all nfs scripts
...
Nmap scan report for 10.11.1.72

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /home 10.11.0.0/255.255.0.0
```

We can mount the home share, and then read it.

```
kali@kali:~$ mkdir home

kali@kali:~$ sudo mount -o nolock 10.11.1.72:/home ~/home/

kali@kali:~$ cd home/ && ls
jenny  joe45  john  marcus  ryuu

kali@kali:~/home$ cd marcus

kali@kali:~/home/marcus$ ls -la
total 24
drwxr-xr-x 2 1014  1014 4096 Jun 10 09:16 .
drwxr-xr-x 7 root root 4096 Sep 17  2015 ..
-rwx------ 1 1014  1014   48 Jun 10 09:16 creds.txt

kali@kali:~/home/marcus$ cat creds.txt
cat: creds.txt: Permission denied
```

We can see that creds.txt is linked to id 1014, so by making our own dummy user, we can read it.



