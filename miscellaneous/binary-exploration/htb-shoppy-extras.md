---
description: >-
  The binary file to get credentials was a small part of the whole box, but I
  focused on breaking it in every single way possible to improve my binary
  skills.
---

# HTB/Shoppy Extras

## Code

```
#include <iostream>
#include <string>

int main() {
    std::cout << "Welcome to Josh password manager!" << std::endl;
    std::cout << "Please enter your master password: ";
    std::string password;
    std::cin >> password;
    std::string master_password = "";
    master_password += "S";
    master_password += "a";
    master_password += "m";
    master_password += "p";
    master_password += "l";
    master_password += "e";
    if (password.compare(master_password) == 0) {
        std::cout << "Access granted! Here is creds !" << std::endl;
        system("cat /home/deploy/creds.txt");
        return 0;
    } else {
        std::cout << "Access denied! This incident will be reported !" << std::endl;
        return 1;
    }
}
```

## Purpose

What we really want to do in all of these methods is to either skip past the if statement and get into the code right after.

Whether we accomplish that by rewriting the binary or by simply jumping is a decision we can make

## Skipping the if statement

We can use gdb for this, and jump past the if statement. It's not that easy though, so let's put into gdb and take a look. I'm gonna break main right at the beginning here to stop just before the main function call. We can then run safely.

<figure><img src="../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

Then, I'm gonna list 200 instructions past main and see where the if statement is. To identify it, we can just look for the JE instruction, which compares two things.

```
pwndbg> x/200i $rip
=> 0x555555555209 <main+4>:     push   rbx
   0x55555555520a <main+5>:     sub    rsp,0x58
   ...
   0x555555555321 <main+284>:   test   al,al
   0x555555555323 <main+286>:   je     0x555555555360 <main+347>
   0x555555555325 <main+288>:   lea    rsi,[rip+0xd44]        # 0x555555556070
   ...
```

We can see that we have the if statement or JE instruction at the relative address main+286. Therefore, we can just jump to main+288 and start the program from there.

```
pwndbg> jump *(main+288)
Continuing at 0x555555555325.
Access granted! Here is creds !
...
You did it!
[Inferior 3 (process 547333) exited normally]
```

## Resetting the register

This time, we're going back into gdb, but not for jumping. Instead, we'll change to JE instruction inside the register to 0, making the computer think the two strings are equal.

We're gonna start this pretty much the same way. Note that we are breaking at \*(main+286) because it is the last address before the if statement.

```
pwndbg> break main
...
pwndbg> r
pwndbg> break *(main+286)
pwndbg> c
pwndbg> info reg
rax            0x0                 0
rbx            0x7fffffffde78      140737488346744
rcx            0x53616d7053616d70  6008203707091610992
rdx            0x4                 4
rsi            0x706d6153          1886216531
rdi            0x66647361          1717859169
rbp            0x7fffffffdd60      0x7fffffffdd60
rsp            0x7fffffffdd00      0x7fffffffdd00
r8             0x1                 1
r9             0x7ffff7e0be78      140737352089208
r10            0x7ffff7c2a6e8      140737350117096
r11            0x7ffff7d42120      140737351262496
r12            0x0                 0
r13            0x7fffffffde88      140737488346760
r14            0x0                 0
r15            0x7ffff7ffd020      140737354125344
rip            0x555555555323      0x555555555323 <main+286>
eflags         0x246               [ PF ZF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```

We see the registers here, and the eflags one is the important one. Basically, the eflags register contains all the boolean flags in the program in one place, and if we set this to 0, which means JE = 0, the program thinks that the two strings are equal. If I forgot to note, JE is the instruction that compares the two addresses, which are strings in this case.

I then did set $eflags=0, and then ni for next instruction, then c for continue.

```
pwndbg> $eflags = 0
pwndbg> ni
pwndbg> c
Credentials Acquired!
```

## Changing the instruction

### Hexedit

To change the instruction, we need to understand a little about instructions and hex for machine code. Basically, each instruction has a code assigned to it, so the machine can interpret exactly what to do with the data. However, this can be changed in hexedit. First, let's find some bytes around the je instruction. JE means jump if equal. However, we're gonna change this to JNE, which is jump if not equal, so that we can skip the "access denied" message and get the credentials immediately.

```
    1321:       84 c0                   test   %al,%al
    1323:       74 3b                   je     1360 <main+0x15b>
    1325:       48 8d 35 44 0d 00 00    lea    0xd44(%rip),%rsi        # 2070 <_ZStL19piecewise_construct+0x68>
```

We can see here that the bytes for the location of the je instruction are c0 74 3b 48 8d and so on. Opening hexedit with the file and pressing / allows us to search for specific bytes, which we'll do here:

<figure><img src="../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Then, we'll overwrite the code for je, which is 74, with jne, which is 75([http://unixwiz.net/techtips/x86-jumps.html](http://unixwiz.net/techtips/x86-jumps.html)). Then, exiting with Ctrl+X, we can run the program again and see that the password no longer matters.

```
┌──(kali㉿kali)-[~/htb/shoppy]
└─$ ./password-managerhexedit                                                                
Welcome to Josh password manager!
Please enter your master password: jsquaredissocool 
Access granted! Here is creds !
You did it!
```

Finally, we'll rewrite the program with ghidra to do the exact same thing.

### Ghidra

Let's open this in ghidra and go to the JE/JZ instruction(the two are basically interchangeable here). Then, I'll right click and select Patch Instruction.

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

I'll then rewrite the JZ to JNZ and export the program. Running it again yields the credentials. Again.

```
┌──(kali㉿kali)-[~/htb/shoppy]
└─$ ./password-managerghidra1
Welcome to Josh password manager!
Please enter your master password: jsquaredissocool
Access granted! Here is creds !
You did it!
```

4 different ways to flex on those binary files :sunglasses:.
