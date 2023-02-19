---
description: JSquared's writeup of the GDB Test Drive Challenge
---

# picoCTF - GDB Test Drive

## Overview&#x20;

Walkthrough of gdb and it's capabilities, including break main and run.&#x20;

### Basis

First off, let's change the permissions on the binary and run gdbme on it

<figure><img src="../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

Note that although it looks like we aren't analyzing gdbme, we are able to interact with it.&#x20;

This isn't much help, so let's convert to asm.

```
kali@kali:~/Downloads$(gdb) layout asm
```

Now we can see that in the address \*(main+99) we have a sleep function, which we want to skip. Create a breakpoint at that location, run the program, and then jump to \*(main+104), which is the next address in the program.

```
(gdb) break *(main+99)
(gdb) run
(gdb) jump *(main+104)
Continuing at 0x55555555532f.                                                                                         │    1414:       c3                      ret
picoCTF{REDACTED}
```

Alternatively, we can also modify the binary file to remove the sleep part. First, we need to find the location of the instructions to sleep and remember the bytes.

<pre><code><strong>...
</strong><strong>132a:       e8 e1 fd ff ff          call   1110 &#x3C;sleep@plt>
</strong><strong>...
</strong></code></pre>

We can see the 5 bytes are e8 e1 fd ff ff. To overwrite them, we'll use a tool called hexedit.

```
kali@kali:~/Downloads$ hexedit gdbme
```

<figure><img src="../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

To look for our 5 bytes, we can hit / and then search for just E8 E1 FD FF FF. This jumps to the location, and we can write over the bytes with 90(which the program sees as a "nothing block"). Ctrl+X to save, and then run again to get the flag.

