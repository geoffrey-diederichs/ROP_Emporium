# ret2win

Let's test the program :

```bash
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

With ghidra we can find those 3 functions :

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

Let's exploit the buffer overflow in pwnme() to redirect the program towards ret2win().

# Dynamic Analysis

Let's find out how many bytes we need to overwrite before accessing the return address :

```gdb
gef➤  r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32)')
Starting program: /home/coucou/Documents/ROP_Emporium/01_ret2win/ret2win <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> 
Breakpoint 1, 0x0000000000400749 in pwnme ()

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x21              
$rbx   : 0x00007fffffffdb68  →  0x00007fffffffdf4b  →  "/home/coucou/Documents/ROP_Emporium/01_ret2win/ret[...]"
$rcx   : 0x00007ffff7ec1a5d  →  0x5b77fffff0003d48 ("H="?)
$rdx   : 0x38              
$rsp   : 0x00007fffffffda20  →  0x4141414141414141 ("AAAAAAAA"?)
$rbp   : 0x00007fffffffda40  →  0x00007fffffffda0a  →  0x000400007ffff7ff
$rsi   : 0x00007fffffffda20  →  0x4141414141414141 ("AAAAAAAA"?)
$rdi   : 0x0               
$rip   : 0x0000000000400749  →  <pwnme+0061> mov edi, 0x40091b
$r8    : 0x00000000004007f0  →  <__libc_csu_fini+0000> repz ret
$r9    : 0x00007ffff7fcfb10  →  <_dl_fini+0000> push r15
$r10   : 0x00007ffff7dd9b08  →  0x0010001200001a3f
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdb78  →  0x00007fffffffdf82  →  "INVOCATION_ID=462553133eb249a98e1baff58ccd460e"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda20│+0x0000: 0x4141414141414141	 ← $rsp, $rsi
0x00007fffffffda28│+0x0008: 0x4141414141414141
0x00007fffffffda30│+0x0010: 0x4141414141414141
0x00007fffffffda38│+0x0018: 0x4141414141414141
0x00007fffffffda40│+0x0020: 0x00007fffffffda0a  →  0x000400007ffff7ff	 ← $rbp
0x00007fffffffda48│+0x0028: 0x00000000004006d7  →  <main+0040> mov edi, 0x400828
0x00007fffffffda50│+0x0030: 0x0000000000000001
0x00007fffffffda58│+0x0038: 0x00007ffff7df16ca  →  <__libc_start_call_main+007a> mov edi, eax
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40073c <pwnme+0054>     mov    rsi, rax
     0x40073f <pwnme+0057>     mov    edi, 0x0
     0x400744 <pwnme+005c>     call   0x400590 <read@plt>
 →   0x400749 <pwnme+0061>     mov    edi, 0x40091b
     0x40074e <pwnme+0066>     call   0x400550 <puts@plt>
     0x400753 <pwnme+006b>     nop    
     0x400754 <pwnme+006c>     leave  
     0x400755 <pwnme+006d>     ret    
     0x400756 <ret2win+0000>   push   rbp
───────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2win", stopped 0x400749 in pwnme (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400749 → pwnme()
[#1] 0x4006d7 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We can see that the rbp is stored right after the variable.

# Exploit
