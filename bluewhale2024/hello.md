# 摩登Pwn  

*都什么年代了还在打传统Pwn  
试试现代的酷炫GUI Pwn！ 
将nc换成您的vnc客户端  
如果不知道用啥，这里有个[TightVNC](https://www.tightvnc.com/)*

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

一道gtk程序，使用vnc连接，观察代码可以在`show_result`函数中发现通过`strtoul`，
我们的输入的在删除-号后被转换成整数

由于存储数据的结构是int，那么只要输入一个大数使符号位为1即可变为负数，拿到flag

## EXPLOIT

```python
print((1 << 32) - 1)
# 输入到输入框中
```

![success](./assets/vnc.png)
