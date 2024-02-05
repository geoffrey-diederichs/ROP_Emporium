from pwn import *

binary = ELF("./split")
string = next(binary.search(b"/bin/cat"))

print(string)
