# ret2shell 

From 0rays.

## 文件分析

下载`ret2shell`, NX off, PIE off, RELRO off 
ghidra分析为64位程序

## 逆向

.bss不可执行，且栈溢出的空间不足以放下shellcode，转而考虑**ret2libc**

## EXPLOIT

```python

```

Done.
