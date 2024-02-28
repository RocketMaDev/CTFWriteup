# Week 3 WriteUp

By: RocketDev  
7 challenges solved

> 可惜了，做encrypt的时候都已经发现xtea变形了，但是来不及了，
> 要不然就第三了

## reverse

### findme

*什么乱七八糟的数据*

程序上来先放两个假flag，然后打印了一段数据

<img src="assets/susData.png" height="100%" width="100%">

一开始没什么感觉，就到字符串查找窗口看了看，好像还藏了个exe？

<img src="assets/susString.png" height="100%" width="100%">

用ImHex提取出数据，再隔三取一组成新的程序进行分析：

```python
binary = b''
with open('findme.dump', 'rb') as dump:
    while True:
        chars = dump.read(4)
        if chars:
            binary += bytes([chars[0]])
        else:
            break
with open('finded.exe', 'wb') as exe:
    exe.write(binary)
```

> Ghidra不需要patch花指令就能反编译哦

当我还在考虑用的是什么算法的时候，突然发现，对一个字节的操作是不涉及输入的其他字节的

<img src="assets/individual.png" height="70%" width="70%">

那么我们可以推测使用和flag一样长的同字符字符串，然后从x64dbg里拿它的加密后数据，
就可以得到加密所产生的差值，再将其反应用到加密的flag上就可以解出flag

```python
def fabs(x):
    if x >= 0:
        return x
    else:
        return 256 + x

added = [0x45, 0xF4, 0x12, 0x6C, 0x84, 0x20, 0x7D, 0xF1, 0x9A, 0x89, 0x45, 0x86, 0xA8, 0x22, 0x48, 0xA7,
 0x71, 0x39, 0x64, 0x10, 0x29, 0x71, 0x78, 0xE0, 0xAF, 0x0C, 0x3D, 0x93, 0x10, 0xFE, 0x23, 0x30]
old = [0x30] * 32 # 输入32个'0'
offset = list(map(lambda x:x[1] - x[0], zip(added, old)))
encoded = [0x7D, 0x2B, 0x43, 0xA9, 0xB9, 0x6B, 0x93, 0x2D,
 0x9A, 0xD0, 0x48, 0xC8, 0xEB, 0x51, 0x59, 0xE9, 0x74, 0x68, 0x8A, 0x45, 0x6B, 0xBA, 0xA7, 0x16,
 0xF1, 0x10, 0x74, 0xD5, 0x41, 0x3C, 0x67, 0x7D]
flag = bytes(map(lambda x:fabs(x[0] + x[1]), zip(encoded, offset)))
print(flag)
```

### mystery

*代码不见了*

在main函数里，只有一个`ptrace`函数，然后翻函数列表，发现`_INIT_1`和`_FINI_1`中存在重要逻辑，
解密key1`keykey`和key2`ban_debug!`后继续查看反编译结果，
将代码喂给New Bing可知用了xmm的代码是算字符串长度的，并且使用了RC4加密算法（有变形）

由于RC4的对称性，可以推测魔改的加密变-为+即可还原flag

```c
// rc4.c
// gcc -o rc4 rc4.c && ./rc4
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
typedef struct _RC4INFO
{
    unsigned char s_box[256]; 
    int t_box[256];
}RC4_INFO,*PRC4_INFO;
 
void rc4_init(PRC4_INFO prc4,unsigned char key[], unsigned int keylen)
{
    int i = 0;
    int j = 0;
    unsigned char tmp;
    if (prc4 == NULL)
    {
        return;
    }
    //init sbox an KeyBox(Tbox)
    for (i = 0; i < 256; i++)
    {
        prc4->s_box[i] = i;
        prc4->t_box[i] = key[i % keylen];
    }
 
    //swap sbox
    for (i = 0; i < 256; i++)
    {
        j = (j + prc4->s_box[i] + prc4->t_box[i]) % 256;
        tmp = prc4->s_box[i];
        prc4->s_box[i] = prc4->s_box[j];
        prc4->s_box[j] = tmp;
    }
}

void rc4_crypt(
    unsigned char data[],       //要加密的数据
    unsigned int datalen,       //要加密的数据长度
    unsigned char key[],        //加密数据所用的Key
    unsigned int keylen,        //加密数据所用的key长度
    int pattern)
{
    int dn = 0;  //data[n]的意思
    int i = 0;
    int j = 0;   // i j 分别用于交换sbox[i] 和 sbox[j]
    int t = 0;   //t = s[i] + s[j]
    unsigned char tmp;
    RC4_INFO rc4;
    rc4_init(&rc4, key, keylen);
 
    for (dn = 0; dn < datalen; dn++)
    {
        i = (i + 1) % 256;
        j = (j + rc4.s_box[i]) % 256;
 
        //swap
        tmp = rc4.s_box[i];
        rc4.s_box[i] = rc4.s_box[j];
        rc4.s_box[j] = tmp;
        //得到T下标用于交换
        t = (rc4.s_box[i] + rc4.s_box[j]) % 256;
        if (pattern)
            data[dn] ^= rc4.s_box[t];
        else
            data[dn] += rc4.s_box[t];
    }
}

int main()
{
    char key[] = "keykey";
    char bandebug[] = "ban_debug!";
    int lenbd = strlen(bandebug);
    rc4_crypt(bandebug, lenbd, key, strlen(key), 1);
    char flag[] = {0x50, 0x42, 0x38, 0x4D, 0x4C, 0x54, 0x90, 0x6F, 0xFE, 0x6F, 0xBC, 0x69, 0xB9, 0x22, 0x7C, 0x16,
    0x8F, 0x44, 0x38, 0x4A, 0xEF, 0x37, 0x43, 0xC0, 0xA2, 0xB6, 0x34, 0x2C, 0 };
    rc4_crypt(flag, strlen(flag), bandebug, lenbd, 0);
    puts(flag);
    return 0;
}
```

> key2 是`ban_debug!`，但是试了一下，可以调试

### encrypt

程序的flag就是由bcrypt加密了一下，从exe里拿一下相关的数据，
再让New Bing生成一下解密代码就拿到flag了

```c
// decrypt.c
#include <windows.h>
#include <ntdef.h>
#include <stdio.h>
#include <bcrypt.h>

void DecryptWithBCrypt() {
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData = 0, cbKeyObject = 0, cbBlockLen = 0, cbBlob = 0;
    PBYTE pbKeyObject = NULL, pbIV = NULL, pbBlob = NULL, pbPlainText = NULL;

    // 初始化解密向量
    BYTE rgbIV[16] = 
        {0x93,  0x6A,  0xF2,  0x25, 0xFA,  0x68,  0x10,  0xB8,
    0xD0,  0x7C,  0x3E,  0x5E, 0x9E,  0xE8,  0xEE,  0x0D};

    // 初始化密钥
    BYTE rgbAES128Key[16] = 
        {0x4C,  0x9D,  0x7B,  0x3E, 0xEC,  0xD0,  0x66,  0x1F,
    0xA0,  0x34,  0xDC,  0x86, 0x3F,  0x5F,  0x1F,  0xE2};

    // 初始化密文
    BYTE rgbCipherText[] = 
    {0xA4, 0xE1, 0x0F, 0x1C, 0x53, 0xBC, 0x42, 0xCD, 0x8E, 0x71, 0x54, 0xB7, 0xF1, 0x75, 0xE3, 0x50,
    0x97, 0x20, 0x71, 0x97, 0xA8, 0x3B, 0x77, 0x61, 0x40, 0x69, 0x68, 0xC1, 0xB4, 0x7B, 0x88, 0x54,
    0x9F, 0x19, 0x03, 0x44, 0x70, 0x78, 0x24, 0x25, 0xF0, 0xA9, 0x65, 0x35, 0x91, 0x3A, 0x04, 0x9C,
    0x4E, 0x66, 0xBE, 0xD2, 0x8B, 0x8B, 0x20, 0x73, 0xCE, 0xA0, 0xCB, 0xE9, 0x39, 0xBD, 0x6D, 0x83};


    // 打开AES算法提供程序
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        goto Cleanup;
    }

    // 计算密钥对象的大小
    if (!NT_SUCCESS(BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) {
        goto Cleanup;
    }

    // 分配密钥对象的内存
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject) {
        goto Cleanup;
    }

    // 生成密钥对象
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAesAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)rgbAES128Key, sizeof(rgbAES128Key), 0))) {
        goto Cleanup;
    }

    // 获取块长度
    if (!NT_SUCCESS(BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0))) {
        goto Cleanup;
    }

    // 分配IV内存
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
    if (NULL == pbIV) {
        goto Cleanup;
    }

    // 使用IV解密
    memcpy(pbIV, rgbIV, cbBlockLen);

    // 分配明文内存
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sizeof(rgbCipherText));
    if (NULL == pbPlainText) {
        goto Cleanup;
    }

    // 解密
    if (!NT_SUCCESS(BCryptDecrypt(hKey, rgbCipherText, sizeof(rgbCipherText), NULL, pbIV, cbBlockLen, pbPlainText, sizeof(rgbCipherText), &cbData, 0))) {
        goto Cleanup;
    }

    // 输出解密后的文本
    printf("Decrypted text: %s\n", pbPlainText);

Cleanup:
    if (hAesAlg) {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }
    if (hKey) {
        BCryptDestroyKey(hKey);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbIV) {
        HeapFree(GetProcessHeap(), 0, pbIV);
    }
    if (pbPlainText) {
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    }
}

int main() {
    DecryptWithBCrypt();
    return 0;
}
```

```sh
gcc -Wextra -Wall -c -o decrypt.o decrypt.c
gcc -lbcrypt -o decrypt.exe decrypt.o
./decrypt.exe
```

## misc

### 简单的取证,不过前十个有红包

*找到veracrypt的文件，拿到flag吧*

下载附件后先用Virtual Box尝试启动了一下，发现需要密码，于是关机解压了vmdk，
在管理员桌面上找到了vera密码，回到根目录下，还看见了`vera.hc`，于是用密码挂载了文件，
打开就是flag

<img src="assets/secret_password.jpg" height="30%" width="30%">
<img src="assets/flagFound.png" height="60%" width="60%">

### 与ai聊天

*跟他聊一聊吧，从他嘴里翘出flag*  
*https://udify.app/chat/oRajccxObXREMLlO*  
*注意请不要过快提问*

莫名其妙就拿到flag了

<img src="assets/aitest.png" height="80%" width="80%">

