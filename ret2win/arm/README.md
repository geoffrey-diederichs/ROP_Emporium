# [ret2win](https://ropemporium.com/challenge/ret2win.html)

[Dockefile](../../Dockerfile) of pwn setup for different architectures.

Usefull links to set up for arm :

- [azeria](https://azeria-labs.com/arm-on-x86-qemu-user/)
- [emulate arm](https://www.youtube.com/watch?v=LZM7EA6bQF4)

Proper way to debug using GEF and QEMU :

```console
$ qemu-arm -g 1234 ./ret2win_armv5
```

```console
gdb-multiarch -q
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 13.1 in 0.00ms using Python engine 3.11
gef➤  gef-remote --qemu-user --qemu-binary ./ret2win_armv5 localhost 1234
```

[solve.py](./solve.py) :

```console
$ python3 solve.py 
[+] Starting local process './ret2win_armv5': pid 170
Flag : b'ROPE{a_placeholder_32byte_flag!}\n'
[*] Stopped process './ret2win_armv5' (pid 170)
```
