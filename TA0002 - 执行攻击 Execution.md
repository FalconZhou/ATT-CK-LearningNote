[TOC]

# TA0002 - 执行攻击 Execution

## T1155 - AppleScript
> https://attack.mitre.org/techniques/T1155/
> 参考：https://sspai.com/post/46912

适用平台：MacOS

macOS和OS X应用程序互相发送AppleEvent消息进行进程间通信(IPC)。通过AppleScript可以为本地或远程IPC编写脚本。Osascript可以执行AppleScript和其他任何开放脚本框架(OSA)语言脚本。使用`osalang`程序可以找到安装在系统上的OSA语言列表。AppleEvent消息可以单独发送，也可以作为脚本的一部分发送。这些事件可以定位打开的窗口，发送击键，并与几乎所有本地或远程打开的应用程序进行交互。

攻击者可以使用它与打开的SSH连接进行交互，移动到远程机器，甚至向用户提供虚假的对话框。这些事件不能远程启动应用程序(尽管它们可以在本地启动)，但如果它们已经在远程运行，则可以与应用程序交互。由于这是一种脚本语言，因此可以使用它来启动更常见的技术，比如通过python启动反向shell。脚本可以从命令行通过`osascript /path/to/script`或`osascript -e“script here”`运行。

## T1191 - Microsoft连接管理器配置文件安装程序 CMSTP
> https://attack.mitre.org/techniques/T1191/
> AppLocker：https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview
> 利用手法：
>
> * https://msitpros.com/?p=3960
> * https://www.4hou.com/technology/11743.html
> * https://pentestlab.blog/2018/05/10/applocker-bypass-cmstp/
> * https://github.com/api0cradle/UltimateAppLockerByPassList

Microsoft连接管理器配置文件安装程序是一种用来安装Connection Manager service profiles的命令行程序b。CMSTP.exe接受INF文件作为参数，并安装用于远程访问链接的服务配置文件。
攻击者可以提供被恶意命令感染的INF文件给CMSTP.exe。类似于Regsvr32 /“Squiblydoo”，CMSTP.exe可能被滥用来从远程服务器加载和执行dll和/或COM scriptlets (SCT)。此执行也可能绕过AppLocker和其他白名单防御，因为CMSTP.exe是一个合法的、有签名的Microsoft应用程序。
CMSTP.exe还可以用来[绕过用户帐户控制](https://attack.mitre.org/techniques/T1088/)，并通过自动提升的COM接口执行来自恶意INF的任意命令。


## T1059 - 命令行接口 Command-Line Interface
> https://attack.mitre.org/techniques/T1059/

攻击者可以通过命令行接口以当前用户权限来执行系统指令、运行软件等。


## T1223 - 已编译HTML文件 Compiled HTML File
> https://attack.mitre.org/techniques/T1223/
> Microsoft HTML Help：https://docs.microsoft.com/zh-cn/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-1-4-sdk
> 利用手法 CVE-2017-8625：
>
> * https://msitpros.com/?p=3909
> * https://www.anquanke.com/post/id/86694
> * https://zhuanlan.zhihu.com/p/41377249

已编译HTML文件（.chm）通常作为Microsoft HTML帮助系统的一部分。CHM文件是各种内容(如HTML文档、图像和与脚本/web相关的编程语言，如VBA、JScript、Java和ActiveX)的压缩编译。CHM内容由 [HTML Help可执行程序(hh.exe)](https://msdn.microsoft.com/zh-cn/windows/desktop/ms524405) 加载的 [IE组件](https://msdn.microsoft.com/zh-cn/windows/desktop/ms644670) 显示。

攻击者可以嵌入恶意负载到CHM文件，发送给用户，然后由用户执行触发。CHM执行还可以绕过在旧的或未打补丁的系统上的应用程序白名单，这些系统不需要通过hh.exe执行二进制文件。


## T1175 - Componet Object Model and Distributed COM


## T1196 - 控制面板 Control Panel Items


## T1173 - 动态数据交换 Dynamic Data Exchange


## T1106 - Execution through API


## T1129 - Execution through Module Load


## T1203 - Exploitation for Client Execution


## T1061 - Graphical User Interface


## T1118 - InstallUtil


## T1152 - Launchctl


## T1168 - Local Job Scheduling



## T1177 - LSASS Driver


## T1170 - Mshta


## T1086 - PowerShell


## T1121 - Regsvcs/Regasm



## T1117 - Regsvr32



## T1085 - Rundll32


## T1053 - Scheduled Task


## T1064 - Scripting


## T1035 - Service Execution


## T1218 - Signed Binary Proxy Execution


## T1216 - Signed Script Proxy Execution


## T1153 - Source


## T1151 - Space after Filename


## T1072 - Third-party Software


## T1154 - Trap


## T1127 - Trusted Developer Utilities


## T1204 - 用户执行 User Execution


## T1047 - WMI (Windows Management Instrumentation)


## T1028 - WinRM (Windows Remote Management)


## T1120 - XSL Script Processing