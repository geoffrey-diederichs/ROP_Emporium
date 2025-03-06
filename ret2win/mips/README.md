# [ret2win](https://ropemporium.com/challenge/ret2win.html)

[Dockefile](../../Dockerfile) of pwn setup for different architectures.

Setting up same way as for arm :

```console
$ qemu-mipsel -g 1234 ./ret2win_mipsel
```

```console
$ gdb-multiarch -q
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 13.1 in 0.00ms using Python engine 3.11
gef➤  set architecture mips
The target architecture is set to "mips".
gef➤  gef-remote --qemu-user --qemu-binary ./ret2win_mipsel localhost 1234
```

[solve.py](./solve.py) :

```console
python3 solve.py 
[+] Starting local process './ret2win_mipsel': pid 6993
Flag : b'ROPE{a_placeholder_32byte_flag!}\n'
[*] Stopped process './ret2win_mipsel' (pid 6993)
```
