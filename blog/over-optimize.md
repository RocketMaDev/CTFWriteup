# 优化，还是过优化？

## 起因

在配置tmux的时候，我希望能看到温度、充电状态和点亮，这三个属性分别存放在三个文件中：
`/sys/class/thermal/thermal_zone0/temp`, `/sys/class/power_supply/ACAD/online`,
`/sys/class/power_supply/BAT1/capacity`中，并配置为这样的显示效果：

<img src="assets/tempAndBat.png" height="30%" width="30%">

为了得到这样的效果，需要在`.tmux.conf`中配置一长串命令：
`#(cut -c -2 /sys/class/thermal/thermal_zone0/temp)C #([ $(cat /sys/class/power_supply/ACAD/online) = 1 ] && echo +)#(cat /sys/class/power_supply/BAT1/capacity)%`

## 开始优化

这实在是太长了！为了简化一些工作，我把显示温度单独抽了出来，用C语言写了一遍

```c
// showtemp.c
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    char buf[3];
    buf[2] = 'C';
    int fd = open("/sys/class/thermal/thermal_zone0/temp", O_RDONLY);
    read(fd, buf, 2);
    write(STDOUT_FILENO, buf, 3);
}
```

然后使用`gcc -O3 -s -o showtemp showtemp.c`将其编译为了elf来替换上面打印温度的部分

## 继续优化

一段时间后，我回看这段命令，感觉仍然有点长，然后想到动不动就两三万的pid，
每3秒就要刷新一次，每次要起4个进程，还是太低效了。于是我直接把所有打印集成到一个程序中

```c
//showtemp.c
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    char symbol[1], buf[15];
    int temp_fd, bat_fd, bat_info_fd;
    int readin, padded = 0;

    if ((temp_fd = open("/sys/class/thermal/thermal_zone0/temp", O_RDONLY)) < 0) {
        memcpy(buf, "-1C ", 4);
        padded = 4;
    } else {
        readin = read(temp_fd, buf, 2);
        if (readin == 0) {
            memcpy(buf, "??C ", 4);
            padded = 4;
            close(temp_fd);
            goto next_state;
        }
        if (buf[1] == '\n') // following return
            readin--;
        memcpy(buf + readin, "C ", 2);
        padded = readin + 2;
        close(temp_fd);
    }

next_state:
    if ((bat_fd = open("/sys/class/power_supply/ACAD/online", O_RDONLY)) < 0) {
        buf[padded++] = '?';
    } else {
        readin = read(bat_fd, symbol, 1);
        if (readin == 0) {
            buf[padded++] = 'x';
            close(bat_fd);
        } else {
            if (*symbol == '1') 
                buf[padded++] = '+';
            close(bat_fd);
        }
    }

    if ((bat_info_fd = open("/sys/class/power_supply/BAT1/capacity", O_RDONLY)) < 0) {
        memcpy(buf + padded, "??%", 3);
        padded += 3;
    } else {
        readin = read(bat_info_fd, buf + padded, 3);
        if (readin == 0) {
            memcpy(buf + padded, "xx%", 3);
            padded += 3;
            close(bat_info_fd);
            goto write_state;
        }
        if (buf[padded + readin - 1] == '\n')
            readin--;
        padded += readin;
        buf[padded++] = '%';
        close(bat_info_fd);
    }

write_state:
    write(STDOUT_FILENO, buf, padded);
}
```

这次我加入了这种边界判断，然后做了完善的测试，把所有打印功能集成到一个程序中，
然而...

## 陷入疯狂

当我在使用gdb调试程序的时候，我看到了熟悉的动态绑定：这个每天都要被运行几千次的程序，
还需要到ld里加载`open`等函数？疑似有点过于低效了！

我用`gcc -S -o showtemp.s -O3 showtemp.c`将程序转换为汇编，然后手动把call
`open`的地方转写为syscall，再编译：`gcc -nostdlib -O3 -s -static -o showtemp showtemp.s`

继续调试，发现程序不是线性运行的，因为编译器输出汇编时，分支跳转并不是按最高可能的情况输出的。
为此，我又加入了以下代码应用于分支判断加速

```c
#define likely(cond)    __builtin_expect((cond), 1)
#define unlikely(cond)  __builtin_expect((cond), 0)
```
并且给整数变量前加上了`register`声明，最后再生成为汇编，并手动syscall，
得到了如下的汇编

```asm
	.file	"showtemp.c"
	.intel_syntax noprefix
	.text
	.align 8
.section .rodata
    .equ SYS_read, 0
    .equ SYS_write, 1
    .equ SYS_open, 2
    .equ SYS_close, 3
    .equ SYS_exit, 60
.LC0:
	.string	"/sys/class/thermal/thermal_zone0/temp"
	.align 8
.LC1:
	.string	"/sys/class/power_supply/ACAD/online"
	.align 8
.LC2:
	.string	"/sys/class/power_supply/BAT1/capacity"
	.p2align 4

.section .text
.global	_start
_start:
.LFB6:
	xor	esi, esi
	xor	eax, eax
	lea	rdi, .LC0[rip]
	sub	rsp, 40
    mov eax, SYS_open
    syscall
	test eax, eax
	js	.L16
	lea	r12, 16[rsp]
	mov	edx, 2
	mov	edi, eax
	mov	ebp, eax
	mov	rsi, r12
    mov eax, SYS_read
    syscall
	mov	r13, rax
	mov	ebx, eax
	test	eax, eax
	je	.L17
.L4:
	cmp	BYTE PTR 17[rsp], 10
	je	.L18
.L5:
	movsx	rax, ebx
	mov	edx, 8259
	mov	edi, ebp
	add	ebx, 2
	mov	WORD PTR [r12+rax], dx
    mov eax, SYS_close
    syscall
.L3:
	xor	esi, esi
	lea	rdi, .LC1[rip]
	xor	eax, eax
    mov eax, SYS_open
    syscall
	mov	ebp, eax
	test eax, eax
	js	.L19
	lea	rsi, 15[rsp]
	mov	edx, 1
	mov	edi, eax
    mov eax, SYS_read
    syscall
	test	eax, eax
	je	.L20
	cmp	BYTE PTR 15[rsp], 49
	jne	.L9
	movsx	rax, ebx
	add	ebx, 1
	mov	BYTE PTR 16[rsp+rax], 43
.L9:
	mov	edi, ebp
    mov eax, SYS_close
    syscall
.L7:
	xor	esi, esi
	lea	rdi, .LC2[rip]
	xor	eax, eax
	movsx	r15, ebx
    mov eax, SYS_open
    syscall
	add	r15, r12
	mov	r14d, eax
	test eax, eax
	js	.L21
	mov	edx, 3
	mov	rsi, r15
	mov	edi, eax
    mov eax, SYS_read
    syscall
	mov	r13, rax
	mov	ebp, eax
	test	eax, eax
	je	.L22
.L12:
	lea	eax, -1[rbx+r13]
	cdqe
	cmp	BYTE PTR 16[rsp+rax], 10
	jne	.L13
	lea	ebp, -1[r13]
.L13:
	lea	eax, 0[rbp+rbx]
	mov	edi, r14d
	lea	ebx, 1[rax]
	cdqe
	mov	BYTE PTR 16[rsp+rax], 37
    mov eax, SYS_close
    syscall
.L11:
	movsx	rdx, ebx
	mov	rsi, r12
	mov	edi, 1
    mov eax, SYS_write
    syscall
    xor edi, edi
    mov eax, SYS_exit
    syscall
.L19:
	movsx	rax, ebx
	add	ebx, 1
	mov	BYTE PTR 16[rsp+rax], 63
	jmp	.L7
.L21:
	mov	WORD PTR [r15], 16191
	add	ebx, 3
	mov	BYTE PTR 2[r15], 37
	jmp	.L11
.L16:
	mov	DWORD PTR 16[rsp], 541274413
	mov	ebx, 4
	lea	r12, 16[rsp]
	jmp	.L3
.L18:
	lea	ebx, -1[r13]
	jmp	.L5
.L20:
	lea	r13d, 1[rbx]
	mov	edi, ebp
	movsx	rbx, ebx
	mov	BYTE PTR 16[rsp+rbx], 120
	mov	ebx, r13d
    mov eax, SYS_close
    syscall
	jmp	.L7
.L22:
	mov	WORD PTR [r15], 30840
	mov	edi, r14d
	add	ebx, 3
	mov	BYTE PTR 2[r15], 37
    mov eax, SYS_close
    syscall
	jmp	.L11
.L17:
	mov	edi, ebp
	mov	DWORD PTR 16[rsp], 541278015
    mov ebx, 4
    mov eax, SYS_close
    syscall
	jmp	.L3
.LFE6:
	.ident	"GCC: (GNU) 14.2.1 20240805"
	.section	.note.GNU-stack,"",@progbits
```

调试的时候也是成功使得程序运行时没有发生任何jmp

## 回顾

当我写完程序后，回过头来看花了过多的时间，因为汇编实在是晦涩难懂，
本来我还想着把逻辑梳理一遍，最后只把call转换成syscall就草草了事。而且，
花这么多时间来“优化”真的值得吗？本来程序运行就花不了多少毫秒，又是把程序转成汇编，
又是加各种优化的，并不能快多少。但是不优化的话，又让我感觉自己没有尽力，
这就是完美主义者的困扰吧。

最近又看到了关于cpu分支判断的文章，原先我以为分支判断错误惩罚是遇到了需要跳转的情况，
可事实上cpu会智能判断是否需要跳转，由此加速程序运行。考虑到优化到这种程序以后，
程序的瓶颈已经到syscall上了，这样的优化看起来就更没必要了。

就像网上说的，优化并不是以自己的范畴优化所有代码，而是重点优化影响系统运行的，
耗时的操作，将你的时间，用在更加重要的事上吧。
