# [ROP Emporium](https://ropemporium.com/)

Solves for every available architectures : x86_64, x86, arm, mips.

[ROP Emporium's](https://ropemporium.com/) challenges teach about ROP chains (Return Oriented Programming) to exploit buffer overflows.

[Docker image](./Dockerfile) used to work with arm and mips.

## [ret2win](./01_ret2win/)

Executing a function.

## [split](./02_split/)

Setting arguments to a function's call.

## [callme](./03_callme/)

Calling functions by their PLT's entries.

## [write4](./04_write4/)

Writing over memory.

## [badchars](./05_badchars/)

Bypassing limitations on bytes to be used.

## [fluff](./06_fluff/)

Finding and using uncommon gadgets.

## [pivot](./07_pivot)

Moving the stack to another location in memory to do a ret2lib.
