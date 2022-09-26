### 破解-Crack
关于破解、二开、去特征我并不想写什么，各种文章太多了，我列几篇，自行参考即可：
* [《CobaltStrike二次开发》](https://www.geekby.site/2020/12/cs%E4%BA%8C%E6%AC%A1%E5%BC%80%E5%8F%91)
* [《对Cobalt Strike进行一点二次开发》](https://www.anquanke.com/post/id/265090)
* [《CobaltStrike 4.3 破解 修复暗桩》](https://maka8ka.cc/post/cobaltstrike-4-3-%E7%A0%B4%E8%A7%A3-%E4%BF%AE%E5%A4%8D%E6%9A%97%E6%A1%A9/)
* [《修改1个字节绕过BeaconEye》](https://www.moonsec.com/5644.html)

{{< admonition tip "补充" >}}

CS4.6修复了该BUG：+ Fixed an issue that caused Cobalt Strike's http listener to be vulnerable when URLs start with "/" as outlined in CVE-2022-23317.

{{< /admonition >}}


### 防破解-AntiCrack
其实很多人并不理解破解的核心是什么？核心不在于你绕过了检查license的Java代码，修改是替换class还是agent方式，还是你patch了多少个防破解检测。

关键点在于完整的功能（官方原版）和AES加密的Key，熟悉的人都知道sleeve下面都是加密文件，没有Key就谈不上破解。当然这两个也只有等泄露。

说到这里又想多说几句，现在很多软件完整版都是通过会员通道+license分发（只要你有完整版都难逃破解的命运），像CS这种将核心模块加密再将Key基于公钥算法保护也算一种比较流行的保护方式。所以Cracker现在最难的是拿完整版和key，这个肯定也会泄露出来，只是时间问题。

言归正传，终上所述，CS的防破解技术主要分为三个方面：
* Authorization校验license
* sleeve的AES加密
* 一些防破解检测，俗称暗桩

通过agent的方式破解，可以防止检测文件篡改，参考https://github.com/Twi1ight/CSAgent

当然agent方式会存在诸多开发不便，因此许多人也会修改class来进行二开，这就不得不聊一下4.5的暗桩检测。

### 4.5的暗桩检测

文件
* 4.5的原版：https://www.ddosi.org/cobaltstrike-4-5/
* 4.5的Key：https://github.com/Twi1ight/CSAgent

暗桩1：
* isPaddingRequired检测crc，和先前的版本一样
* beacon/BeaconC2，BeaconC2函数调用this.data.shouldPad(isPaddingRequired());
* 30分钟后，所有任务改为向beacon发退出命令

暗桩2：
* common/Starter2，initialize函数if (!A(paramClass)) {System.exit(0);}
* aggressor.dialogs/ConnectDialog和server/Resources均有调用
* 检测crc，检测不过，直接退出

暗桩3：
* aggressor/Aggressor，localRuntimeMXBean.getInputArguments()，检测"-javaagent:"参数，这个对修改class无效
* common/Starter，同上Starter2，initialize函数if (!A(paramClass)) {System.exit(0);}
* aggressor/Aggressor、common/Requirements和server/Teamserver均有调用

暗桩4：
* common/Helper.startHelper函数
* 检测Starter2.class、ConnectDialog.class、Resources.class的crc
* aggressor.windows/KeystrokeBrowser、CredentialManager、ScreenshotBrowser均有调用
* crc检测不过，直接退出

暗桩5：
* beacon/CommandBuilder，类构造函数中初始化
* 包含"-javaagent:"参数（同上），则触发检测
* 检测BeaconC2、BeaconData、SleevedResource、SleeveSecurity.class的crc值，不相等则4小时后触发检测
* 触发检测后，所有下发的任务命令改为0x06，即不干活

根据上面的信息，反编译代码，找到各个检测函数，patch移除暗桩即可。