# Split

Let's test the program :

```
$ ./split                 
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> test
Thank you!

Exiting
```

# Static analysis

With ghidra we can find those functions :

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

We need to exploit the buffer overflow in pwnme() to run usefulFunction().

# Dynamic analysis

Let's find out how many bytes we need to overwrite before accessing the return address :

```gdb
gef➤  r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32)')
Starting program: /home/coucou/Documents/ROP_Emporium/02_split/split <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> 
Breakpoint 1, 0x0000000000400735 in pwnme ()

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x21              
$rbx   : 0x00007fffffffdb78  →  0x00007fffffffdf5b  →  "/home/coucou/Documents/ROP_Emporium/02_split/split"
$rcx   : 0x00007ffff7ec1a5d  →  0x5b77fffff0003d48 ("H="?)
$rdx   : 0x60              
$rsp   : 0x00007fffffffda30  →  0x4141414141414141 ("AAAAAAAA"?)
$rbp   : 0x00007fffffffda50  →  0x00007fffffffda0a  →  0xdb7800007fffffff
$rsi   : 0x00007fffffffda30  →  0x4141414141414141 ("AAAAAAAA"?)
$rdi   : 0x0               
$rip   : 0x0000000000400735  →  <pwnme+004d> mov edi, 0x40083f
$r8    : 0x00000000004007d0  →  <__libc_csu_fini+0000> repz ret
$r9    : 0x00007ffff7fcfb10  →  <_dl_fini+0000> push r15
$r10   : 0x00007ffff7dd9b08  →  0x0010001200001a3f
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdb88  →  0x00007fffffffdf8e  →  "INVOCATION_ID=462553133eb249a98e1baff58ccd460e"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda30│+0x0000: 0x4141414141414141	 ← $rsp, $rsi
0x00007fffffffda38│+0x0008: 0x4141414141414141
0x00007fffffffda40│+0x0010: 0x4141414141414141
0x00007fffffffda48│+0x0018: 0x4141414141414141
0x00007fffffffda50│+0x0020: 0x00007fffffffda0a  →  0xdb7800007fffffff	 ← $rbp
0x00007fffffffda58│+0x0028: 0x00000000004006d7  →  <main+0040> mov edi, 0x400806
0x00007fffffffda60│+0x0030: 0x0000000000000001
0x00007fffffffda68│+0x0038: 0x00007ffff7df16ca  →  <__libc_start_call_main+007a> mov edi, eax
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400728 <pwnme+0040>     mov    rsi, rax
     0x40072b <pwnme+0043>     mov    edi, 0x0
     0x400730 <pwnme+0048>     call   0x400590 <read@plt>
 →   0x400735 <pwnme+004d>     mov    edi, 0x40083f
     0x40073a <pwnme+0052>     call   0x400550 <puts@plt>
     0x40073f <pwnme+0057>     nop    
     0x400740 <pwnme+0058>     leave  
     0x400741 <pwnme+0059>     ret    
     0x400742 <usefulFunction+0000> push   rbp
───────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped 0x400735 in pwnme (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400735 → pwnme()
[#1] 0x4006d7 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We can see that the rbp is stored right after the variable : our payload will have an offset of 32 bytes, 8 bytes to overwrite the rbp, and finally the address of ret2win.

# Exploit
