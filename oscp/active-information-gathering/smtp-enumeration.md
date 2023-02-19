# SMTP Enumeration

```
┌──(kali㉿kali)-[~]
└─$ nc -nv 10.11.1.217 25
(UNKNOWN) [10.11.1.217] 25 (smtp) open
220 hotline.localdomain ESMTP Postfix
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
^C
```

We can see here that we can ask if a user exists, and SMTP will gladly tell us if it does.
