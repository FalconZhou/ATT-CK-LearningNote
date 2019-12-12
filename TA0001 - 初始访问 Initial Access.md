[TOC]

# TA0001 - 初始访问 Initial Access
Initial Access是为了通过使用各种技术在被攻击方获取最初的“立足点”，从而进行下一步攻击。


## T1189 - 水坑攻击 Drive-by Compromise
> https://attack.mitre.org/techniques/T1189/
> ID: T1189
> 战术: Initial Access
> 平台: Windows, Linux, macOS, SaaS
> 权限需求: User
> 数据源: Packet capture, Network device logs, Process use of network, Web proxy, Network intrusion detection system, SSL/TLS inspection
> Version: 1.1
>
> ---
> https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/


Drive-by Compromise是指攻击者通过用户在正常访问网站过程中获取系统访问权限。攻击者通常将用户的浏览器作为攻击目标，也可能会去获取应用的Token。
攻击方法有：
* 对被访问的网站注入恶意代码（如JavaScript、Iframes、跨站脚本）
* 向合法广告提供商付费并投放恶意广告
* 内置的web应用程序接口可用于插入任何类型的对象，这些对象可以用来显示网页内容或者包含可以在访问客户端上执行的脚本（如论坛帖子、评论及其他用户可控的web内容）

典型的水坑攻击过程：
* 用户访问攻击者可控制的网页
* 脚本自动执行，通常会查看浏览器和插件的版本，寻找已有漏洞
  * 可能会要求用户启用脚本或Active组件，并忽略警告
* 找到易受攻击版本后，EXP代码将传递到浏览器
* 如果利用成功，除非存在其他保护措施，否则恶意代码将在用户系统执行
  * 在某些情况下，在提供漏洞利用代码之前，需要在初始扫描后再次访问网站。

攻击者还可能利用受感染的网站来引导用户访问恶意应用，导致应用的Tokens被窃取。


## T1190 - 攻击公开的应用 Exploit Public-Facing Application
> https://attack.mitre.org/techniques/T1190/
> ID: T1190
> 战术: Initial Access
> 平台: Linux, Windows, macOS, AWS, GCP, Azure
> 数据源: Azure activity logs, AWS CloudTrail logs, Stackdriver logs, Packet capture, Web logs, Web application firewall logs, Application logs
> Version: 2

Exploit Public-Facing Application是指攻击者利用被攻击者**面向公众的应用**中的弱点，从而达到攻击的目的。弱点可能是Bug、故障或设计缺陷。这些应用通常是web，但也包括Database（MySQL、Oracle等），标准服务（SMB、SSH等）以及其他具有Internet可访问套接字的应用。
如果应用程序托管在云上，则攻击可能会损害基础实例（the underlying instance）。这可以使攻击者获得云API权限或利用弱认证，从而获得配置的管理权限（access management policies）。
对于website来说，常见的攻击类型可参考 [OWASP TOP10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)和[CWE TOP25](https://cwe.mitre.org/top25/index.html)


## T1133 - 外部远程服务 External Remote Services
> https://attack.mitre.org/techniques/T1133/
> ID: T1133
> 战术: Persistence, Initial Access
> 平台: Windows
> 权限需求: User
> 数据源: Authentication logs
> CAPEC ID: [CAPEC-555](https://capec.mitre.org/data/definitions/555.html)
> Version: 2.0
>
> ---
> https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/

Remote Service是指类似于RDP、Telnet、SSH、VPN、Citrix等，允许从外部环境介入内部企业网络资源的服务。这些服务通常会用远程服务网关统一管理，并通过凭证来使用服务。如[WinRM](https://attack.mitre.org/techniques/T1028/)也有类似作用。
攻击者可以使用远程服务来最初访问和在网络内停留。通常需要[合法帐户](https://attack.mitre.org/techniques/T1078)才能使用该服务。可以通过篡改凭据或在攻击企业网络之后从用户那里获取凭据来获得账号。在操作过程中，可以将对远程服务的访问用作[冗余访问](https://attack.mitre.org/techniques/T1108/)的一部分。


缓解方法

> 通过巡检登录时间、登录行为等来检查攻击。



## T1200 - 硬件攻击 Hardware Additions
> https://attack.mitre.org/techniques/T1200/
> ID: T1200
> 战术: Initial Access
> 平台: Windows, Linux, macOS
> 数据源: Asset management, Data loss prevention
> Version: 1.0


Hardware Additions 是指 攻击者通过引入硬件作为访问系统的媒介。已知的已有：
* [被动网络窃听](https://ossmann.blogspot.com/2011/02/throwing-star-lan-tap.html)
* [中间人加密破解](http://www.bsidesto.ca/2015/slides/Weapons_of_a_Penetration_Tester.pptx)
* [击键注入](https://www.hak5.org/blog/main-blog/stealing-files-with-the-usb-rubber-ducky-usb-exfiltration-explained)
* [通过DMA读取内核存储](https://www.youtube.com/watch?v=fXthwl6ShOg)
* [向现有网络添加新无线节点](https://arstechnica.com/information-technology/2012/03/the-pwn-plug-is-a-little-white-box-that-can-hack-your-network/)

缓解措施：
* 通过资产管理系统集中化管理硬件资产，可以有效发现网络中不应该存在的硬件。
* 终端传感器可以通过USB、Thunderbolt和其他外部设备通信端口检测硬件的添加。


## T1091 - 通过可移动介质重放攻击 Replication Through Removable Media
> https://attack.mitre.org/techniques/T1091/
> ID: T1091
> 战术: Lateral Movement, Initial Access
> 平台: Windows
> 系统环境需求: Removable media allowed, Autorun enabled or vulnerability present that allows for code execution
> 权限需求: User
> 数据源: File monitoring, Data loss prevention
> Version: 1.0


攻击者通过将恶意软件复制到可移动媒体并利用媒体插入系统执行时的Autorun特性进入系统，可能是未连接或隔离网络中的系统。（如通过USB传染）
* 在横向渗透时，这可能是通过修改存储在可移动媒体上的可执行文件或通过复制恶意软件并将其重命名为看起来像合法文件来诱使用户在单独的系统上执行它而发生的。 
* 在初始访问时，这可能是通过手动操作介质，修改用于初始格式化介质的系统或修改介质固件本身而发生的。


## T1193 - 鱼叉式钓鱼-附件 Spearphishing Attachment
> https://attack.mitre.org/techniques/T1193/
> ID: T1193
> 战术: Initial Access
> 平台: Windows, macOS, Linux
> 数据源: File monitoring, Packet capture, Network intrusion detection system, Detonation chamber, Email gateway, Mail server
> CAPEC ID: [CAPEC-163](https://capec.mitre.org/data/definitions/163.html)
> Version: 1.0


Spearphishing Attachment 指攻击者通过构造诱导性邮件，向用户发送恶意附件。通常依赖于诱导[用户执行](https://attack.mitre.org/techniques/T1204/)来使恶意附件运行。
常用文件类型：
* Office文档
* 可执行文件（PE、ELF等）
* PDF
* 存档文件（压缩包？）


常用手法：
* 邮件正文中构造诱导性语句，使用户点开附件
* 诱导用户绕过系统验证（是否确认打开文件、是否确认给文件权限等）
* 正文带密码，用来解密压缩文件（为了绕过附件检测）
* 扩展名伪造和图标伪造

缓解方法：
* 防病毒软件
* 网络入侵防御
* 限制基于web的内容
* 针对员工的信息安全意识培训

检测：
* 网络入侵检测系统
* 邮件网关
* 沙箱
* 基于主机的防病毒软件


## T1192 - 鱼叉式钓鱼-链接 Spearphishing Link
> https://attack.mitre.org/techniques/T1192/
> ID: T1192
> 战术: Initial Access
> 平台: Windows, macOS, Linux, Office 365, SaaS
> 数据源: Packet capture, Web proxy, Email gateway, Detonation chamber, SSL/TLS inspection, DNS records, Mail server
> CAPEC ID: [CAPEC-163](https://capec.mitre.org/data/definitions/163.html)
> Version: 1.1
>
> ---
> https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks

Spearphishing Link 指攻击者通过在邮件中放置下载链接，用来躲避防御检测。


## T1194 - 鱼叉式钓鱼-服务 Spearphishing via Service
> https://attack.mitre.org/techniques/T1194/
> ID: T1194
> 战术: Initial Access
> 平台: Windows, macOS, Linux
> 数据源: SSL/TLS inspection, Anti-virus, Web proxy
> CAPEC ID: [CAPEC-163](https://capec.mitre.org/data/definitions/163.html)
> Version: 1.0

Spearphishing via Service 指攻击者不通过企业邮件服务，而是通过第三方服务（如：社交媒体、个人邮件服务以及其他非企业控制服务）来将钓鱼链接或钓鱼附件传给用户。


## T1195 - 供应链攻击 Supply Chain Compromise
> https://attack.mitre.org/techniques/T1195/
> ID: T1195
> 战术: Initial Access
> 平台: Linux, Windows, macOS
> 数据源: Web proxy, File monitoring
> CAPEC ID: [CAPEC-437](https://capec.mitre.org/data/definitions/437.html), [CAPEC-438](https://capec.mitre.org/data/definitions/438.html), [CAPEC-439](https://capec.mitre.org/data/definitions/439.html)
> Version: 1.1

Supply Chain Compromise 指通过攻击系统的供应链（依赖产品）来达到攻击的目的。
供应链各阶段包括：
* 开发工具
* 开发环境
* 源代码仓库
* 源代码的开源依赖
* 软件更新/分发机制
* 受损/感染的系统镜像
* 使用修改的版本替换合法软件
* 销售经修改/伪造的产品给经销商
* 发货拦截（Shipment interdiction）


## T1199 - 利用可信任关系 Trusted Relationship
> https://attack.mitre.org/techniques/T1199/
> ID: T1199
> 战术: Initial Access
> 平台: Linux, Windows, macOS, AWS, GCP, Azure, SaaS
> 数据源: Azure activity logs, Stackdriver logs, AWS CloudTrail logs, Application logs, Authentication logs, Third-party application logs
> Version: 2.0


Trusted Relationship 指攻击者通过攻击与受害者相关的第三方组织来达到攻击目的。针对第三方组织访问受害者的网络，受到的审查或保护相对较少。第三方组织包括但不限于IT服务承包商、托管安全提供商、基础架构承包商（包括物理意义上的组织）。


## T1078 - 利用合法账号 Valid Accounts
> https://attack.mitre.org/techniques/T1078/
> ID: T1078
> 战术: Defense Evasion, Persistence, Privilege Escalation, Initial Access
> 平台: Linux, macOS, Windows, AWS, GCP, Azure, SaaS, Office 365
> 权限需求: User, Administrator
> 有效权限: User, Administrator
> 数据源: AWS CloudTrail logs, Stackdriver logs, Authentication logs, Process monitoring
> 可绕过防御类型: Firewall, Host intrusion prevention systems, Network intrusion detection system, Process whitelisting, System access controls, Anti-virus
> CAPEC ID: [CAPEC-560](https://capec.mitre.org/data/definitions/560.html)
> Version: 2.0

Valid Accounts 指攻击者通过窃取、社工等方式获取特定用户或服务的账号凭证，来获得初始访问的权限。
攻击者可能会使用的账户分为三类：
* 默认账户（Default）
  默认账户指操作系统内置的账户，如Windows 的Guest或Administrator账户。也指
* [本地账户（Local）
  [本地账户](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)指由组织配置的，供用户、远程支持、服务使用，或者供单个系统或服务的认证 的账户。
* 域账户（Domain）
  域账户是用来管理AD域服务管理的账户。