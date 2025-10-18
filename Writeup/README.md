# Dangerous Worm

> **不要在实体机上运行！！！！！！！！！！！这是恶意软件！！！！！！！！！！！！**
>
> **不要在实体机上运行！！！！！！！！！！！这是恶意软件！！！！！！！！！！！！**
>
> **不要在实体机上运行！！！！！！！！！！！这是恶意软件！！！！！！！！！！！！**

故事发生在一个普通的办公室。Luminoria 的同事，我们称他为 Paff，不幸成为了这次攻击的“0号病人”。

有一天，Paff 收到了一个伪装成客户合同的钓鱼邮件，并运行了其中的恶意附件。他电脑上的杀毒软件没能识别这个新型病毒，很快，他的电脑就被攻击者完全控制。这个病毒的核心功能之一，就是在公司内网中寻找下一个目标。

Luminoria 的单位给他配了一台工作电脑，虽然它的配置很高，但是 Luminoria 是个恋旧的人，他偏偏是钉子户，他安装的系统为远古科技 Windows 10 x64 Professional 1511（2016年4月），并且没有启用 Windows Update。

在 2114 年 5 月 12 日（周五），Luminoria 下班后，没有将电脑关机，而是进行了锁屏以后，就直接离开公司了。因为攻击者对 Luminoria 的公司非常的熟悉，所以他选择在大家都下班以后，发动蠕虫病毒进行内网横向渗透攻击。好巧不巧，Luminoria 的电脑中招了。

2114 年 5 月 14 日（周一），Luminoria 回到了公司，发现自己放在桌面上的重要数据文件变成乱码了，这可把 Luminoria 急坏了！

你是公司的应急响应专家，现在拿到了 Luminoria 电脑在文件被加密期间的内存镜像。IT团队已经定位到攻击流量来自 Paff 的电脑，但他们需要你来分析 Luminoria 电脑上究竟发生了什么。你需要从内存中找出加密程序运行时留下的关键证据，特别是用于加密文件的密钥，以便尝试恢复被锁定的文件。

1. 攻击者在 Luminoria 的电脑上新建了一个用户，这个用户叫什么？（例如 `ExampleAccount`）
2. 攻击者使用的是什么漏洞进行攻击的？（CVE-YYYY-XXXX，例如CVE-2025-8088）
3. 攻击者在电脑上留下的加密密钥是什么？（不带空格的十六进制，全大写）
4. Luminoria 的重要数据文件中有一段非常重要的密钥，请你找到它

作答的时候需要将四个问题的答案用下划线连接后，套上 `flag{}` 头进行作答，假设答案为 `ExampleAccount` `CVE-2025-8088` `AABBCCDD` `thiS-iS-4_t0k3n`，那么最后作答的答案应该为 `flag{10.0.0.8_ExampleAccount_CVE-2025-8088_AABBCCDD_thiS-iS-4_t0k3n}`

## 解题

本题主要是当时在羊城杯打了一个病毒+内存取证组合的题目，所以我也想出一个来玩玩，于是就出现了这么一个题目。

### 以正确的方式打开

首先，这题是一题内存取证，所以我们要用合适的工具打开，你也可以用 Vol2/3 都是没问题的，不过我在这里推一个 LovelyMem 系列（Lite 免费，Luxe 收费，可以用 Lite 做）

我下面直接用 Luxe 了

### 获取账户

我们得知道账户从哪里获取，在内存取证中，我们一般通过注册表获取账户

而这个过程通常用 MemProcFS，因为它的注册表注册表数据比较全。在 MemProcFS 中，我们选择注册表时间线功能，直接搜索 `HKLM\SAM\SAM\Domains\Account\Users\Names`，后面的就是用户名了

![](https://cdn.bili33.top/gh/GDUTMeow/Challenge-Dangerous-Worm/Writeup/img/LovelymemLuxe_3GN2VZa27O.png)

这里可以看到有 5 个用户

- Luminoria
- Administrator
- Guest
- DefaultAccount
- PaffCream$

第一个是 Luminoria 的个人用户，可以暂时放过，而 2~4 是 Windows 安装的时候默认会创建的用户，看起来没有什么怪的，也可以先放过

但是第五个 `PaffCream$`，这里带了个 `$`，是个影子账户，可以认为是攻击者创建的账户，所以第一个问题的答案为 `PaffCream$`

### 利用的漏洞（推断）

题目里面说是攻击者通过 Paff 的电脑作为跳板来攻击 Luminoria 的电脑的，所以一定是利用了某个漏洞进行的，我们先查看电脑上现在有什么服务，用 Vol3 查看一下

```shell
$ python -m volatility3 -f vuln10.vmem netscan --output-dir output
```

把端口从小到大排列一下，能够看到这些比较关键的端口

- 135 -> Windows RPC 端点映射器
- 137 -> NetBIOS 名称服务
- 138 -> NetBIOS 数据报服务
- 139 -> NetBIOS 会话服务
- 445 -> SMB 服务
- 1900 -> UPnP
- 3702 -> WS-Discovery 网络设备发现

剩下的都可以不管，通过端口我们可以发现这台电脑是打开了局域网发现与共享功能的

DHCPv6 和 UPnP 基本上没法利用；135 是通过远程调用的，可以持保留意见；137-139、445是局域网文件共享用的，而结合题目所说的 `远古科技 Windows 10 x64 Professional 1511（2016年4月），并且没有启用 Windows Update`，说明 Luminoria 的电脑存在一定的漏洞，而 SMB 的漏洞比较知名的是 MS17-010（永恒之蓝），当时的 WannaCry 所利用的就是这个漏洞，可以持保留意见。

看样子好像暂时没办法继续了，先下一题

### 获取加密密钥

这个要用到 filescan，扫描一下电脑里面有什么

```shell
$ python -m volatility3 -f vuln10.vmem filescan --output-dir output
```

既然加密的东西是个程序，那我们可以先搜一下 `.exe`，然后能看到有个 `\\Users\\Luminoria\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\安全中心.exe` 很可疑

![](https://cdn.bili33.top/gh/GDUTMeow/Challenge-Dangerous-Worm/Writeup/img/LovelymemLuxe_JIKR7ebLE1.png)

给它 dump 出来

```shell
$ python.exe -m volatility3 -f vuln10.vmem -o output windows.dumpfiles --physaddr 0xe0014fdb54e0
$ python.exe -m volatility3 -f vuln10.vmem -o output windows.dumpfiles --virtaddr 0xe0014fdb54e0
```

得到两个文件

![](https://cdn.bili33.top/gh/GDUTMeow/Challenge-Dangerous-Worm/Writeup/img/explorer_QI7xQZAfCB.png)

用 DIE 看一下两个文件，发现大一点的那个会被识别出来是 pyinstaller 打包的程序

![](https://cdn.bili33.top/gh/GDUTMeow/Challenge-Dangerous-Worm/Writeup/img/die_NlcagM2b95.png)

先用 pyinstxtractor 转成 pyc

```shell
$ uv run pyinstxtractor.py file.0xe0014fdb54e0.0xe0014f993690.DataSectionObject.安全中心.exe.dat
[+] Processing file.0xe0014fdb54e0.0xe0014f993690.DataSectionObject.安全中心.exe.dat
[+] Pyinstaller version: 2.1+
[+] Python version: 3.8
[+] Length of package: 9300165 bytes
[+] Found 124 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_setuptools.pyc
[+] Possible entry point: main.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.8 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: file.0xe0014fdb54e0.0xe0014f993690.DataSectionObject.安全中心.exe.dat

You can now use a python decompiler on the pyc files within the extracted directory
```

然后用 pylingual 把源码弄出来

```shell
$ pylingual .\main.pyc
```

结果反编译出来发现是个调用起

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'main.py'
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

from encryptor import main
if __name__ == '__main__':
    main()
```

可以看到这里有一个 encryptor 包，但我们在目录里没看到，那就要转向 `PYZ.pyz_extracted`，里面就有 `encryptor` 文件夹，把这几个文件都反编译回去

```shell
$ pylingual __init__.pyc cipher.pyc context.pyc utils.pyc vars.pyc
```

然后就可以得到大部分源码了，通过 `context.py` 可以看到，这里有密钥的位置和目标

```python
SECRET_PATH = '%APPDATA%\\Microsoft\\Crypto\\Keys\\TPM.key'
TARGET = ['C:\\Users\\%USERNAME%\\Desktop', 'C:\\Users\\%USERNAME%\\Documents', 'C:\\Users\\%USERNAME%\\Pictures', 'C:\\Users\\%USERNAME%\\Videos', 'C:\\Users\\%USERNAME%\\Music', 'C:\\Users\\%USERNAME%\\Downloads']
```

现在我们就可以去找密钥了，直接搜索并把密钥 dump 出来，位置在 `\\Users\\Luminoria\\AppData\\Roaming\\Microsoft\\Crypto\\Keys\\TPM.key`，打开后得到 key 为 `F7 F5 9F 7C BB 4B 6E 12 A8 E3 65 B4 76 8A 75 D9`，所以第三问答案为 `F7F59F7CBB4B6E12A8E365B4768A75D9`

### 获取数据文件中的密钥

在 `cipher.py` 可以看到，这是一个 AES-CBC 加密

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'encryptor\\cipher.py'
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from encryptor.vars import Global
def encrypt(data: bytes, params: Global) -> bytes:
    cipher = AES.new(params.KEY, AES.MODE_CBC, bytes([b ^ params._ for b in params.IV]))
    cipher_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher_bytes
```

而 IV 可以在 `vars.py` 看到

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'encryptor\\vars.py'
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
class Global:
    def __init__(self, SECRET_PATH):
        self._ = 102
        self.IV = b'4U+U\x0b\x04\x03\x14\x12\t3\x16"&\x12#'
        if os.path.exists(SECRET_PATH):
            with open(SECRET_PATH, 'rb') as f:
                self.KEY = f.read(16)
        else:
            os.makedirs(os.path.dirname(SECRET_PATH), exist_ok=True)
            with open(SECRET_PATH, 'wb') as f:
                self.KEY = os.urandom(16)
                f.write(self.KEY)
```

并且在进行加密的时候，跟一个 `_` 进行了异或

```python
    cipher = AES.new(params.KEY, AES.MODE_CBC, bytes([b ^ params._ for b in params.IV]))
```

所以稍微写一个小脚本算出真正的 IV

```python
original_iv = b'4U+U\x0b\x04\x03\x14\x12\t3\x16"&\x12#'
xor_key = 102

real_iv = bytes([b ^ xor_key for b in original_iv])
print(real_iv.hex())
```

得到结果为 `52334d336d626572746f557044407445`，转换为字符串为 `R3M3mbertoUpD@tE`

在代码里面，我们可以看到加密后的文件会被加上 `.paff` 的文件后缀，所以直接搜后缀，发现桌面上有两个被加密的文件

至此，我们拿到了所有加密用的东西，可以去解密了，我们把两个加密后的文件拿出来，丢进赛博厨子

因为加密之后还加了一个 `PAFF` 魔术头才保存的，所以要先去掉

然后在 `Secr3t.db.paff` 解密后可以看到有一个 `My Token is:`，后面的 UUID 就是密钥了：`303c535a-1a26-4dbc-8034-64be01627d78`

![](https://cdn.bili33.top/gh/GDUTMeow/Challenge-Dangerous-Worm/Writeup/img/msedge_xB94ZYWq7t.png)

### 验证 CVE 编号

给的文件中还有一个 `Security.txt.paff`，我们一起拿去解码看看

![](https://cdn.bili33.top/gh/GDUTMeow/Challenge-Dangerous-Worm/Writeup/img/msedge_tV9JLG5qqs.png)

可以看到 CVE 编号是 `CVE-2017-0144`，正好与 MS17-010 吻合，所以最后的 CVE 编号为 `CVE-2017-0144`

### 组合答案

1. 攻击者在 Luminoria 的电脑上新建了一个用户，这个用户叫什么？ -> `PaffCream$`
2. 攻击者使用的是什么漏洞进行攻击的？（CVE-YYYY-XXXX，例如CVE-2025-8088） -> `CVE-2017-0144`
3. 攻击者在电脑上留下的加密密钥是什么？（不带空格的十六进制，全大写） -> `F7F59F7CBB4B6E12A8E365B4768A75D9`
4. Luminoria 的重要数据文件中有一段非常重要的密钥，请你找到它 -> `303c535a-1a26-4dbc-8034-64be01627d78`

flag 为 flag{PaffCream$_CVE-2017-0144_F7F59F7CBB4B6E12A8E365B4768A75D9_303c535a-1a26-4dbc-8034-64be01627d78}
