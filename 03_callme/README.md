# Callme

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

In the description of this challenge, we're told we need to call the function callme_one(), callme_two() and callme_three() in that order and with the arguments 0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d.

The read function in pwnme() expects 512 bytes even the local_28 variable is 32 bytes long. Let's exploit this buffer overflow to redirect program execution.

# Dynamic analysis

Let's find out how many bytes we need to send to modify the return address :

```gdb
gef➤  r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32)')
```

```gdb
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda10│+0x0000: 0x4141414141414141	 ← $rsp, $rsi
0x00007fffffffda18│+0x0008: 0x4141414141414141
0x00007fffffffda20│+0x0010: 0x4141414141414141
0x00007fffffffda28│+0x0018: 0x4141414141414141
0x00007fffffffda30│+0x0020: 0x00007fffffffda0a  →  0x4141000000000040 ("@"?)	 ← $rbp
0x00007fffffffda38│+0x0028: 0x0000000000400887  →  <main+0040> mov edi, 0x4009e7
0x00007fffffffda40│+0x0030: 0x0000000000000001
0x00007fffffffda48│+0x0038: 0x00007ffff7a456ca  →  <__libc_start_call_main+007a> mov edi, eax
```
