# SafeNote

from 浙江省赛决赛 2023

## 文件分析

下载`SafeNote`, 保护全开  
ghidra分析为64位程序

## 解题思路

我既没参加省赛，也没做出来这道题，主要是在这里写写收获，
做出来的wp会贴在下面

文件里引入了gmp这一我从来没见过的东西，据查是数学运算库，
其有一个数据类型：`mpz_t`，结构是`{int _mp_size, int _mp_alloc, long **_mp_d}`
其中`_mp_d`是malloc出来的数组，会对堆产生影响

文件的解题关键是虽然`password`是从`/dev/urandom`里拿的，与时间无关，
但是加解密的参数依然是以时间为种子，因此可以模拟攻击解密（好像没用到allocnote）

## 别人的wp

[lewiserii's wp](https://lewiserii.github.io/%E7%AB%9E%E8%B5%9B/%E7%AC%AC%E5%85%AD%E5%B1%8A%E6%B5%99%E6%B1%9F%E7%9C%81%E5%A4%A7%E5%AD%A6%E7%94%9F%E7%BD%91%E7%BB%9C%E4%B8%8E%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9Bwp.html#%E5%86%B3%E8%B5%9B-SafeNote)
