[TOC]

## TA0003 - 持久性 Persistence

在这个环节攻击者试图保持他们的立足点（持久性）。

攻击者利用持久性技术以确保在重启、更改凭证和其他可能切断其访问的事件发生之后，仍能保持对系统的访问。



### [T1156 - .bash_profile and .bashrc](https://attack.mitre.org/techniques/T1156/)

> Tactic: Persistence
>
> Platform: Linux, macOS
>
> Permissions Required: User, Administrator
>
> Data Sources: File monitoring, Process monitoring, Process command-line parameters, Process use of network
>
> Version: 1.1

`~/.bash_profile` 和 `~/.bashrc`  是包含 shell 命令的 shell 脚本。These files are executed  in a user's context when a new shell opens or when a user logs in so  that their environment is set correctly. `~/.bash_profile` is executed for login shells and `~/.bashrc`  is executed for interactive non-login shells. This means that when a  user logs in (via username and password) to the console (either locally  or remotely via something like SSH), the `~/.bash_profile`  script is executed before the initial command prompt is returned to the  user. After that, every time a new shell is opened, the `~/.bashrc`  script is executed. This allows users more fine-grained control over  when they want certain commands executed. These shell scripts are meant  to be written to by the local user to configure their own environment. 

攻击者可能会通过插入任意的shell命令来滥用这些shell脚本，这些命令可用于执行其他二进制文件以获得持久性。每当用户登录或打开一个新shell时，修改后的~/。bash_profile和/或~ /。将执行bashrc脚本。



Adversaries  may abuse these shell scripts by inserting arbitrary shell commands  that may be used to execute other binaries to gain persistence. Every  time the user logs in or opens a new shell, the modified ~/.bash_profile  and/or ~/.bashrc scripts will be executed.



~ /。bash_profile和~ /。bashrc是包含shell命令的shell脚本。当新shell打开或用户登录以正确设置其环境时，这些文件将在用户的上下文中执行。~ /。bash_profile用于登录shell和~/。bashrc用于交互式的非登录shell。这意味着当用户(通过用户名和密码)登录到控制台(本地或通过类似SSH的远程方式)时，使用~/。bash_profile脚本在初始命令提示符返回给用户之前执行。之后，每次打开一个新shell， ~/。执行bashrc脚本。这允许用户在希望执行某些命令时进行更细粒度的控制。这些shell脚本由本地用户编写，以配置他们自己的环境。




### [T1015 - Accessibility Features 辅助功能](https://attack.mitre.org/techniques/T1015/)

> Tactic: Persistence, Privilege Escalation
> Platform: Windows
> Permissions Required: Administrator
> Effective Permissions: SYSTEM
> Data Sources: Windows Registry, File monitoring, Process monitoring
> CAPEC ID: [CAPEC-558](https://capec.mitre.org/data/definitions/558.html)
> Contributors: Paul Speulstra, AECOM Global Security Operations Center
> Version: 1.0

Windows 自带的辅助功能（轻松使用）特性可以在用户登录之前通过键组合启动，攻击者可以修改这些程序的启动方式，从而在不登录系统的情况下调用命令提示符或后门程序。

两个常见的辅助功能是 Windows 粘滞键（C:\Windows\System32\sethc.exe，5 次 shift）和 Windows 辅助工具管理器（C:\Windows\System32\utilman，Windows + U）。根据不同的 Windows 版本，攻击者可能会以不同的方式利用这些特性。在较新的 Windows 版本中，被替换的二进制文件需要进行数字签名校验，二进制文件必须驻留在 `%systemdir%\` 目录下，并且受到 WFP/WRP（Windows File / Resource Protection） 的保护。“调试器（debugger）”方法很可能成为一种利用方案，因为它不需要替换相应的二进制文件。

两种方法举例如下：

在 Windows XP 和 Windows Server 2003 R2 及其以后的版本，可以直接通过对可执行程序的二进制文件进行替换来实现攻击。比如，将 C:\Windows\System32 目录下的 utilman.exe 替换为 cmd.exe 或另一个后门程序。之后，在通过远程程桌面协议（[RDP](https://attack.mitre.org/techniques/T1076)）连接时，在登录界面按下适当的组合键就可以导致所替换的文件以 SYSTEM 权限执行。

对于 Windows Vista 和 Windows Server 2008 及其以后的版本，需要使用“调试器”方法。比如，可以修改注册表项以配置 cmd.exe 或另一个后门程序作为某个辅助功能（例如 utilman.exe）的“调试器”。修改注册表后，在键盘上或使用 RDP 连接时在登录界面按下适当的组合键将导致“调试器”程序以 SYSTEM 权限执行。

其他可能以类似方式利用的辅助功能：

- 屏幕键盘: C:\Windows\System32\osk.exe
- 放大镜: C:\Windows\System32\Magnify.exe
- 讲述人: C:\Windows\System32\Narrator.exe
- 显示切换器: C:\Windows\System32\ DisplaySwitch.exe
- 应用程序切换器: C:\Windows\System32\ AtBroker.exe



### [T1098 - Account Manipulation 账户操作](https://attack.mitre.org/techniques/T1098/)

> Tactic: Credential Access, Persistence
>
> Platform: Windows, Office 365, Azure, GCP, Azure AD, AWS
>
> System Requirements: Exchange  email account takeover: Sufficient permission to run the  Add-MailboxPermission PowerShell cmdlet (depending on parameters used,  may require more permission)
>
> Permissions Required: Administrator
>
> Data Sources: Authentication logs, API monitoring, Windows event logs, Packet capture
>
> Contributors: Jannie Li, Microsoft Threat Intelligence Center (MSTIC); Praetorian; Tim MalcomVetter
>
> Version: 2.0



### [T1182 - AppCert DLLs 注入](https://attack.mitre.org/techniques/T1182/)

> Tactic: Persistence, Privilege Escalation
> Platform: Windows
> Permissions Required: Administrator, SYSTEM
> Effective Permissions: Administrator, SYSTEM
> Data Sources: Loaded DLLs, Process monitoring, Windows Registry
> Version: 1.0

利用 AppCertDlls 注册表项来实现 DLL 注入。Windows 中的大量 API 函数（CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, WinExec）都会加载处于注册表 `HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls` 下的 DLL 文件。所以只需要在 AppCertDlls 中写入 DLL 的绝对路径，就可以将此注册表项下的 DLL 加载到调用 Windows API 函数每个的进程中。

与进程注入（[Process Injection](https://attack.mitre.org/techniques/T1055)）类似，攻击者可以利用这个值在独立进程的上下文中加载和运行恶意 DLL，以获得持久性和权限提升。



### [T1103 - AppInit DLLs 注入](https://attack.mitre.org/techniques/T1103/)

> Tactic: Persistence, Privilege Escalation
> Platform: Windows
> Permissions Required: Administrator
> Data Sources: Loaded DLLs, System calls, Windows Registry, Process monitoring, Process command-line parameters
> Version: 1.0

利用 AppInit DLLs 注册表项来实现 DLL 注入。Windows 允许加载了 user32.dll 的进程加载处于注册表 `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` 或 `HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` 下的 DLL 文件。所以只需要在 AppInit_DLLs 下写入 DLL 的绝对路径，并把数值改为 1，就可以使得所有加载 user32.dll 的进程全部加载目标路径的 DLL 文件。由于 user32.dll 是一个非常常用的库，在实际情况下，这个 DLL 几乎会被加载到每一个进程。

与进程注入（[Process Injection](https://attack.mitre.org/techniques/T1055)）类似，攻击者可以利用这个值在独立进程的上下文中加载和运行恶意 DLL，以获得持久性和权限提升。

在 Windows 8 及以后的版本中，当启用安全启动（secure boot）时，将禁用 AppInit DLL 的功能。



### [T1138 - Application Shimming 应用兼容性](https://attack.mitre.org/techniques/T1138/)

> Tactic: Persistence,Privilege Escalation
> Platform: Windows
> System Requirements: Secure boot disabled on systems running Windows 8 and later
> Permissions Required: Administrator
> Effective Permissions: Administrator, SYSTEM
> Data Sources: Loaded DLLs, Process monitoring, Windows Registry
> Version: 1.0

#### 概述

Application Shim（Microsoft Windows Application Compatibility Infrastructure/Framework，应用程序兼容性基础架构/框架）的作用是为了在操作系统中保持向后兼容性，shim 被用来充当程序和 Windows 操作系统之间的缓冲区，当程序执行时将引用 shim 缓存来确定程序是否需要使用自定义数据库（.sdb）。如果需要使用，则自定义数据库将根据需要使用 [Hooking](https://attack.mitre.org/techniques/T1179) 技术重定向代码，以便应用程序可以在不同的 Windows 版本下执行。

> 使用 sdbinst.exe 命令行工具来部署自定义数据库文件

当前已安装的兼容性修补程序（shims）的列表保存在以下目录：

- `%WINDIR%\AppPatch\sysmain.sdb`
- `hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb`

自定义数据库存储在：

- `%WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom`
- `hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom`

为了保证兼容性修补程序的安全，Windows 将它们设计为在用户模式下运行，不能修改内核，并且必须具有管理员权限才能进行安装。但是，某些兼容性修补程序可以绕过 UAC（[Bypass User Account Control](https://attack.mitre.org/techniques/T1088/)，RedirectEXE）、将 DLL 注入进程（InjectDLL）、禁用数据执行保护（Data Execution Prevention，DisableNX）和结构化异常处理（Structure Exception Handling，DisableSEH），以及截获内存地址（GetProcAddress）。类似于 Hooking 技术，攻击者可以利用这些兼容性修补程序执行一些恶意行为，如提高特权，安装后门，禁用安全防御软件，如 Windows Defender 等。

#### 检测

- 相关工具
  - Shim-Process-Scanner - 检查每个运行进程的内存中是否有任何 shim 标志
  - Shim-Detector-Lite - 检查自定义 shim 数据库的安装
  - Shim-Guard - 监视任何安装 shim 的注册表行为
  - ShimScanner - 检查在内存中活跃的兼容性修补程序
  - ShimCacheMem - 从内存中提取 shim 缓存
- 监视 sdbinst.exe 的进程执行和命令行参数



### [T1131 - Authentication Package](https://attack.mitre.org/techniques/T1131/)

> Tactic: Persistence
>
> Platform: Windows
>
> Permissions Required: Administrator
>
> Data Sources: DLL monitoring, Windows Registry, Loaded DLLs
>
> Version: 1.0



### [T1197 - BITS Jobs](https://attack.mitre.org/techniques/T1197/)

> Tactic: Defense Evasion, Persistence
>
> Platform: Windows
>
> Permissions Required: User, Administrator, SYSTEM
>
> Data Sources: API monitoring, Packet capture, Windows event logs
>
> Defense Bypassed: Firewall, Host forensic analysis
>
> Contributors: Ricardo Dias; Red Canary
>
> Version: 1.0



### [T1067 - Booktkit](https://attack.mitre.org/techniques/T1067/)

> Tactic: Persistence
>
> Platform: Linux, Windows
>
> Permissions Required: Administrator, SYSTEM
>
> Data Sources: API monitoring, MBR, VBR
>
> Version: 1.0



### [T1176 - Browser Extensions](https://attack.mitre.org/techniques/T1176/)

> Tactic: Persistence
>
> Platform: Linux, macOS, Windows
>
> Permissions Required: User
>
> Data Sources: Network protocol analysis, Packet capture, System calls, Process use of network, Process monitoring, Browser extensions
>
> Contributors: Justin Warner, ICEBRG
>
> Version: 1.0



### [T1042 - Change Default File Association](https://attack.mitre.org/techniques/T1042/)

> Tactic: Persistence
>
> Platform: Windows
>
> Permissions Required: User, Administrator, SYSTEM
>
> Data Sources: Windows Registry, Process monitoring, Process command-line parameters
>
> CAPEC ID: [CAPEC-556](https://capec.mitre.org/data/definitions/556.html)
>
> Contributors: Stefan Kanthak; Travis Smith, Tripwire
>
> Version: 1.0



### [T1109 - Component Firmware](https://attack.mitre.org/techniques/T1109/)

> Tactic: Defense Evasion, Persistence
>
> Platform: Windows
>
> System Requirements: Ability to update component device firmware from the host operating system.
>
> Permissions Required: SYSTEM
>
> Data Sources: Disk forensics, API monitoring, Process monitoring, Component firmware
>
> Defense Bypassed: File monitoring, Host intrusion prevention systems, Anti-virus
>
> Version: 1.0



### [T1122 - Componet Object Model Hijacking](https://attack.mitre.org/techniques/T1122/)

> Tactic: Defense Evasion, Persistence
>
> Platform: Windows
>
> Permissions Required: User
>
> Data Sources: Windows Registry, DLL monitoring, Loaded DLLs
>
> Defense Bypassed: Autoruns Analysis
>
> Contributors: ENDGAME
>
> Version: 1.0



### [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)

> Tactic: Persistence
>
> Platform: Linux, macOS, Windows, AWS, GCP, Azure AD, Azure, Office 365
>
> Permissions Required: Administrator
>
> Data Sources: Office  365 account logs, Azure activity logs, AWS CloudTrail logs, Process  monitoring, Process command-line parameters, Authentication logs,  Windows event logs
>
> Contributors: Microsoft Threat Intelligence Center (MSTIC); Praetorian
>
> Version: 2.0



### [T1038 - DLL Search Order Hijacking DLL 搜索顺序劫持 ](https://attack.mitre.org/techniques/T1038/)

> Tactic: Persistence, Privilege Escalation, Defense Evasion
> Platform: Windows
> System Requirements: Ability to add a DLL, manifest file, or .local file, directory, or junction.
> Permissions Required: User, Administrator, SYSTEM
> Effective Permissions: User, Administrator, SYSTEM
> Data Sources: File monitoring, DLL monitoring, Process monitoring, Process command-line parameters
> Defense Bypassed: Process whitelisting
> CAPEC ID: [CAPEC-471](https://capec.mitre.org/data/definitions/471.html)
> Contributors: Stefan Kanthak; Travis Smith, Tripwire
> Version: 1.0

Windows 系统使用一种常见的方法来查找需要加载到程序中的 DLL 动态链接库，攻击者可能会利用 Windows DLL 的搜索顺序和模糊指定 DLL 的程序，来获得持久性和权限提升。

攻击者可以利用 DLL 预加载（也被称为二进制植入攻击），使应用程序加载恶意 DLL。本地 DLL 预加载攻击的方法是将一个与模糊指定 DLL 同名的恶意 DLL 放在 Windows 程序对合法 DLL 进行搜索之前的位置，这个位置通常是程序当前的工作目录；当程序在加载 DLL 之前将其当前目录设置为远程位置（如 Web 共享）时，就会发生远程 DLL 预加载攻击。

攻击者还可以通过替换现有 DLL 或修改 `.manifest` 或 `.local` 重定向文件、目录或文件夹映射来直接修改程序加载 DLL 的方式，使程序加载恶意 DLL 文件。

最终获得到的权限由加载恶意 DLL 的程序的权限决定，根据程序权限的不同，攻击者可以使用这种技术将权限从用户升级到 Admin 或 SYSTEM 权限。



### [T1157 - Dylib Hijacking Dylib 劫持](https://attack.mitre.org/techniques/T1157/)

> Tactic: Persistence, Privilege Escalation
> Platform: macOS
> Permissions Required: User
> Effective Permissions: Administrator, root
> Data Sources: File monitoring
> CAPEC ID: [CAPEC-471](https://capec.mitre.org/data/definitions/471.html)
> Version: 1.0

macOS 和 OS X 系统使用一种常见的方法来查找需要加载到程序中的 Dylib 动态链接库，攻击者可以利用模糊路径来植入 Dylib，以获得特权升级或持久性。

攻击者可以通过查看应用程序使用了什么 Dylib，然后在合法 Dylib 的搜索路径之前植入同名的恶意 Dylib，这个位置通常是程序当前的工作目录。

如果将程序在高于当前用户的权限级别上运行，那么当将 Dylib 加载到应用程序中时，Dylib 也将在更高的权限上运行，使攻击者实现权限提升。



### [T1519 - Emond 守护进程](https://attack.mitre.org/techniques/T1519/)

> Tactic: Persistence, Privilege Escalation
> Platform: macOS
> Permissions Required: Administrator
> Effective Permissions: root
> Data Sources: File monitoring, API monitoring
> Contributors: Ivan Sinyakov
> Version: 1.0

#### 概述

攻击者可以通过在事件触发器（predictable event triggers）上执行恶意指令来使用事件监视器守护进程（Event Monitor Daemon，emond）建立持久性。Emond 是一个守护进程（[Launch Daemon](https://attack.mitre.org/techniques/T1160)），它接受来自各种服务的事件，通过规则采取行动。在 `/sbin/emond` 处的 emond 程序将从 `/etc/emond.d/rules/` 中读取规则（plist格式），一旦有显式事件发生，就立即采取行动。如果路径 `/private/var/db/emondClients` 下没有文件存在 emond 服务将不会启动。

攻击者可以利用这个服务，编写一条规则，在定义的事件发生时执行恶意指定。当 emond 服务使用 root 权限执行时，攻击者就可以将特权从管理员升级到 root 权限。

#### 检测

- 通过检测 `/etc/emond.d/rules/` 和 `/private/var/db/emondClients` 目录下的文件创建或修改操作，来监视 emond 规则的创建。



### [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)

> Tactic: Persistence, Initial Access
>
> Platform: Windows
>
> Permissions Required: User
>
> Data Sources: Authentication logs
>
> CAPEC ID: [CAPEC-555](https://capec.mitre.org/data/definitions/555.html)
>
> Contributors: Daniel Oakley; Travis Smith, Tripwire
>
> Version: 2.0



### [T1044 - File System Permissions Weakness 文件系统权限缺陷](https://attack.mitre.org/techniques/T1044/)

> Tactic: Persistence, Privilege Escalation
> Platform: Windows
> Permissions Required: Administrator, User
> Effective Permissions: SYSTEM, User, Administrator
> Data Sources: File monitoring, Services, Process command-line parameters
> CAPEC ID: [CAPEC-17](https://capec.mitre.org/data/definitions/17.html)
> Contributors: Stefan Kanthak; Travis Smith, Tripwire
> Version: 1.0

进程可以自动执行指定的二进制文件，如果不正确地设置了包含目标二进制文件的文件系统目录的权限或二进制文件本身的权限，则可能使用用户级权限用另一个二进制文件覆盖目标二进制文件，并由原始进程执行。如果原始进程和线程在更高的权限级别下运行，那么被替换的二进制文件也将在更高的权限级别下执行。

攻击者可以利用这个缺陷将正常的二进制文件替换为恶意的二进制文件，作为在更高权限级别执行代码的一种方式。如果将执行进程设置为在特定时间或特定事件期间运行（如：系统启动），则此技术也可用于持久性攻击。

主要利用方式有两种：

- Windows 服务：攻击者用恶意程序替换 windows 服务中正常的可执行文件。
- 可执行的安装程序：在安装过程中，安装程序通常使用 `%TEMP%` 目录中的子目录来解压二进制文件，当安装程序创建子目录和文件时，它们通常不会设置适当的权限来限制写访问，这就允许攻击者可以利用这种缺陷，在子目录中执行不受信任的代码，或者覆盖安装过程中使用的二进制文件。这种行为同时可能与 [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1038) 和 [Bypass User Account Control](https://attack.mitre.org/techniques/T1088) 相关。由于一些安装程序可能需要提升权限，这将导致攻击者植入的恶意代码也以更高权限执行。

## 

## T1158 - Hidden Files and Directories

## 

### [T1179 - Hooking 钩子](https://attack.mitre.org/techniques/T1179/)

> Tactic: Persistence, Privilege Escalation, Credential Access
> Platform: Windows
> Permissions Required: Administrator, SYSTEM
> Data Sources: API monitoring, Binary file metadata, DLL monitoring, Loaded DLLs, Process monitoring, Windows event logs
> Version: 1.0

Windows 进程通常利用 API 函数来执行需要重用系统资源的任务，Hooking 的目的就是重定向调用这些功能，实现方式有以下几种：

- 过程钩子（hooks procedures），对于消息、击键和鼠标输入等事件进行拦截并执行指定的代码。
- IAT 钩子（import address table hooking），对进程的 IAT 进行修改，而 IAT 中存储了指向导入 API 函数的指针。
- 内联钩子（inline hooking）, 覆盖 API 函数中的第一个字节来重定向代码流。

与进程注入（[Process Injection](https://attack.mitre.org/techniques/T1055)）类似，攻击者可以 Hooking 在另一个进程的上下文中加载和隐蔽执行恶意代码，同时允许访问进程的内存，进行权限提升和持久性。

Hooking 通常被 [Rootkits](https://attack.mitre.org/techniques/T1014) 用来隐藏文件、进程、注册表项和其他对象，以隐藏恶意软件和其相关行为。

## 

## T1062 - Hypervisor

## 

### [T1183 - Image File Execution Options Injection IFEO 注入](https://attack.mitre.org/techniques/T1183/)

> Tactic: Privilege Escalation, Persistence, Defense Evasion
> Platform: Windows
> Permissions Required: Administrator, SYSTEM
> Data Sources: Process monitoring, Windows Registry, Windows event logs
> Defense Bypassed: Autoruns Analysis
> Contributors: Oddvar Moe, @oddvarmoe
> Version: 1.0

映像文件执行选项（IFEO）使得开发人员能够将调试器 attach 到要调试的应用程序上，开发人员通过注册表设置 IFEOs 值，就可以将软件 attach 到一个要调试的程序上，之后只要一启动软件，被 attach 的程序也会一起启动。利用这种方式，攻击者可以修改此注册键值将恶意代码注入到目标软件中，当目标软件启动时，被注入的恶意代码就会一起启动，同时获得持久性和权限提升。



## 

## T1525 - Implant Container Image

## 

## T1215 - Kernel Modules and Extensions

## 

## T1159 - Launch Agent

## 

### [T1160 - Launch Daemon 守护进程](https://attack.mitre.org/techniques/T1160/)

> Tactic: Persistence, Privilege Escalation
> Platform: macOS
> Permissions Required: Administrator
> Effective Permissions: root
> Data Sources: Process monitoring, File monitoring
> Version: 1.0

根据苹果的官方文档，当 macOS 和 OS X 启动时，将运行 launchd 来完成系统初始化，这个过程会从 `/System/Library/LaunchDaemons` 和 `/Library/LaunchDaemons` 中的属性列表（plist）文件中为每个计划启动的系统级守护进程加载参数。

攻击者可以创建一个新的守护进程，使用 launchd 或 launchctl 将 plist 加载到特定目录，以在启动时执行这个守护进程，守护进程的名称可以伪装成系统进程或正常软件。由于守护进程可以使用管理员权限创建，在 root 权限下执行，因此攻击者可以将权限从管理员升级到 root。

## 

## T1152 - Launchctl

## 

## T1161 - LC_LOAD_DYLIB Addition

## 

## T1168 - Local Job Scheduling

## 

## T1162 - Login Item

## 

## T1037 - Logon Scripts

## 

## T1177 - LSASS Driver

## 

## T1031 - Modify Existing Service

## 

## T1128 - Netsh Helper DLL



### [T1050 - New Service 新服务](https://attack.mitre.org/techniques/T1050/)

> Tactic: Persistence, Privilege Escalation
> Platform: Windows
> Permissions Required: Administrator, SYSTEM
> Effective Permissions: SYSTEM
> Data Sources: Windows Registry, Process monitoring, Process command-line parameters, Windows event logs
> CAPEC ID: [CAPEC-550](https://capec.mitre.org/data/definitions/550.html)
> Contributors: Pedro Harrison
> Version: 1.0

当操作系统启动时，服务会在后台启动以执行系统功能。服务的配置信息，包括服务的可执行文件路径，都存储在 Windows 注册表中。

攻击者可以创建一个新的服务，通过使用程序与服务交互程序或直接修改注册表将其配置为在启动时执行，服务名称可以伪装成系统进程或正常软件来进行伪装（[Masquerading](https://attack.mitre.org/techniques/T1036)）。服务可以使用管理员权限创建，但在 SYSTEM 权限下执行，因此攻击者可以使用 Windows 服务将权限从管理员升级到 SYSTEM。攻击者也可以通过服务执行（[Service Execution](https://attack.mitre.org/techniques/T1035)）直接启动服务。



## T1137 - Office Application Startup



### [T1034 - Path Interception 路径拦截](https://attack.mitre.org/techniques/T1034/)

> Tactic: Persistence, Privilege Escalation
> Platform: Windows
> Permissions Required: User, Administrator, SYSTEM
> Effective Permissions: User, Administrator, SYSTEM
> Data Sources: File monitoring, Process monitoring
> CAPEC ID: [CAPEC-159](https://capec.mitre.org/data/definitions/159.html)
> Contributors: Stefan Kanthak

当可执行文件被放在特定的路径中，由其他应用程序而不是预期的程序执行时，就会发生路径拦截。比如，在一个有漏洞的应用程序的当前工作目录中放置 cmd 的副本，使该应用程序调用 `CreateProcess` 函数加载 cmd 程序或 BAT 文件。

在执行路径拦截时，攻击者可能会利用多个明显的漏洞或错误配置，比如：未引用的路径（Unquoted Paths）、路径环境变量错误配置（PATH Environment Variable Misconfiguration）和搜索顺序劫持（Search Order Hijacking）。



## T1150 - Plist Modification

## 

## T1205 - Port Knocking



### [T1013 - Port Monitors 端口监控](https://attack.mitre.org/techniques/T1013/)

> Tactic: Persistence, Privilege Escalation
>
> Platform: Windows
>
> Permissions Required: Administrator, SYSTEM
>
> Effective Permissions: SYSTEM
>
> Data Sources: File monitoring, API monitoring, DLL monitoring, Windows Registry, Process monitoring
>
> Contributors: Stefan Kanthak; Travis Smith, Tripwire
>
> Version: 1.0

可以通过调用端口监视器的 API 来在启动时加载特定的DLL。这个 DLL 可以位于 `C:\Windows\System32` 下并将在系统引导时被 `spoolsv.exe`加载，此进程会在系统权限下运行。另外，如果权限允许将 DLL 的绝对路径写入`HKLM\SYSTEM\CurrentControlSet\Control\Print\`中，则可以加载任意 DLL。

该注册表项包含以下条目：

- 本地端口
- 标准的 TCP / IP 端口
- USB 监控
- WSD 端口

攻击者可以使用此技术在启动时加载恶意代码，这些恶意代码将在系统重新启动时持续存在，并以 SYSTEM 权限执行。



### [T1504 - PowerShell Profile 配置文件](https://attack.mitre.org/techniques/T1504/)

> Tactic: Persistence, Privilege Escalation
>
> Platform: Windows
>
> Permissions Required: User, Administrator
>
> Data Sources: Process monitoring, File monitoring, PowerShell logs
>
> Contributors: Allen DeRyke, ICE
>
> Version: 1.0

在某些情况下，攻击者可以通过利用 [PowerShell](https://attack.mitre.org/techniques/T1086) 的配置文件来获得持久性和提升权限。PowerShell 配置文件（`profile.ps1`）是 PowerShell 启动时运行的脚本，可以用作自定义用户环境的登录脚本。PowerShell 本身支持多个配置文件，具体取决于用户或主机程序。例如，PowerShell 控制台、PowerShell ISE 或 Visual Studio Code 都有不同的配置文件。

攻击者可以修改这些配置文件，使其包含任意命令、函数、模块和 PowerShell 驱动，以获得持久性。每次用户打开 PowerShell 会话时，除非在启动时使用 `-NoProfile` 参数，否则将执行修改后的脚本。

如果 PowerShell 配置文件中的脚本是由具有更高权限的帐户（例如域管理员）加载和执行的，则攻击者也可以获得权限提升。



## T1163 - Rc.common

## 

## T1164 - Re-opend Applications

## 

## T1108 - Redundant Access

## 

## T1060 - Registry Run Keys / Startup Folder



### [T1053 - Scheduled Task 计划任务](https://attack.mitre.org/techniques/T1053/)

> Tactic: Execution, Persistence, Privilege Escalation
>
> Platform: Windows
>
> Permissions Required: Administrator, SYSTEM, User
>
> Effective Permissions: SYSTEM, Administrator, User
>
> Data Sources: File monitoring, Process monitoring, Process command-line parameters, Windows event logs
>
> Supports Remote:  Yes
>
> CAPEC ID: [CAPEC-557](https://capec.mitre.org/data/definitions/557.html)
>
> Contributors: Prashant Verma, Paladion; Leo Loobeek, @leoloobeek; Travis Smith, Tripwire; Alain Homewood, Insomnia Security
>
> Version: 1.1

诸如 [at](https://attack.mitre.org/software/S0110) 和 [schtasks](https://attack.mitre.org/software/S0111) 之类的实用工具，以及 Windows 任务调度程序（Windows Task Scheduler），可以用来自定义在某个日期和时间执行程序或脚本，也可以在远程系统上调度任务。条件是满足使用 RPC 的身份验证，并打开文件和打印机共享。在远程系统上调度任务通常需要成为远程系统上 Administrators 组的成员。

攻击者可以使用计划任务在系统启动时执行程序，以实现持久性和获得系统权限，或在指定帐户的上下文中运行进程。



## T1180 - Screensaver

## 

## T1101 - Security Support Provider

## 

## T1505 - Server Software Component



### [T1058 - Service Registry Permissions Weakness 服务注册权限缺陷](https://attack.mitre.org/techniques/T1058/)

> Tactic: Persistence, Privilege Escalation
>
> Platform: Windows
>
> System Requirements: Ability to modify service values in the Registry
>
> Permissions Required: Administrator, SYSTEM
>
> Effective Permissions: SYSTEM
>
> Data Sources: Process command-line parameters, Services, Windows Registry
>
> CAPEC ID: [CAPEC-478](https://capec.mitre.org/data/definitions/478.html)
>
> Contributors: Matthew Demaske, Adaptforward; Travis Smith, Tripwire
>
> Version: 1.1

Windows 在 `HKLM\SYSTEM\CurrentControlSet\Services` 的注册表项中存储本地服务配置信息。可以通过服务控制器、sc.exe、PowerShell 或 Reg 等工具操作存储在服务注册表项下的信息，以修改服务的执行参数。

如果没有正确设置用户和组的权限并允许访问服务的注册表项，则攻击者可以更改服务的相关路径，使其指向攻击者控制下的其他可执行程序。当服务启动或重新启动时，由攻击者控制的程序就将执行，从而允许攻击者获得持久性和权限提升。



### [T1166 - Setuid and Setgid 标志位](https://attack.mitre.org/techniques/T1166/)

> Tactic: Privilege Escalation, Persistence
>
> Platform: Linux, macOS
>
> Permissions Required: User
>
> Effective Permissions: Administrator, root
>
> Data Sources: File monitoring, Process monitoring, Process command-line parameters
>
> Version: 1.0

当在 Linux 或 macOS 上为应用程序设置了 setuid（SUID） 或 setgid（SGID） 位时，应用程序将分别以拥有用户或组的特权运行。通常应用程序是在当前用户的上下文中运行的，而与拥有该应用程序的用户或组无关。任何用户都可以为自己的应用程序指定设置 setuid 或 setgid 标志，而无需在 sudoers 文件中创建一个必须由 root 用户完成的条目。

攻击者可以利用这一点来进行 shell 转义，或者利用应用程序中的 setsuid 或 setgid 位的漏洞来让代码在不同的用户上下文中运行。此外，攻击者可以在他们自己的恶意软件上使用这种机制，以确保他们能够在更高权限的上下文中执行。



## T1023 - Shortcut Modification

## 

## T1198 - SIP and Trust Provider Hijacking

## 

## T1165 - Startup Items

## 

## T1019 - System Firmware

## 

## T1501 - Systemd Service

## 

## T1209 - Time Providers

## 

## T1154 - Trap



### [T1078 - Valid Accounts 有效账户](https://attack.mitre.org/techniques/T1078/)

> Tactic: Defense Evasion, Persistence, Privilege Escalation, Initial Access
>
> Platform: Linux, macOS, Windows, AWS, GCP, Azure, SaaS, Office 365
>
> Permissions Required: User, Administrator
>
> Effective Permissions: User, Administrator
>
> Data Sources: AWS CloudTrail logs, Stackdriver logs, Authentication logs, Process monitoring
>
> Defense Bypassed: Firewall,  Host intrusion prevention systems, Network intrusion detection system,  Process whitelisting, System access controls, Anti-virus
>
> CAPEC ID: [CAPEC-560](https://capec.mitre.org/data/definitions/560.html)
>
> Contributors: Netskope; Mark Wee; Praetorian
>
> Version: 2.0

攻击者可以使用凭据访问技术窃取特定用户或服务帐户的凭据，或者通过社会工程在侦察过程中更早地捕获凭据，以获得初始访问权限。

攻击者可能使用的帐户可以分为三类：默认帐户、本地帐户和域帐户。默认帐户是那些内置在操作系统中的帐户，如 Windows 系统上的 Guest 或管理员帐户。本地帐户是组织为用户、远程支持、服务或单个系统上的管理员而配置的帐户。域帐户是由 Active Directory 域服务管理的，可以包含用户、管理员和服务。

被利用的登录凭证可以用来绕过系统内各种资源的访问控制，甚至可以用于持久访问远程系统和外部服务，如 VPNs、Outlook Web access 和远程桌面服务。也可能授予更高的权限以访问特定的受限区域，同攻击者可能会选择不使用恶意软件或工具，只使用这些凭证进行合法的访问，使自己更难以被发现。



### [T1100 - Web Shell](https://attack.mitre.org/techniques/T1100/)

> Tactic: Persistence, Privilege Escalation
>
> Platform: Linux, Windows, macOS
>
> System Requirements: Adversary access to Web server with vulnerability or account to upload and serve the Web shell file.
>
> Effective Permissions: SYSTEM, User
>
> Data Sources: Anti-virus, Authentication logs, File monitoring, Netflow/Enclave netflow, Process monitoring
>
> CAPEC ID: [CAPEC-650](https://capec.mitre.org/data/definitions/650.html)
>
> Version: 1.0

Web shell 是放置在可公开访问的 Web 服务器上的 Web 脚本，允许攻击者将 Web 服务器用作进入网络的网关。Web shell 可以提供一组要执行的函数，或者在运行 Web 服务器的系统上提供一个命令行访问接口。除了服务器端脚本外，Web shell 可能还有一个用于连接 Web 服务器的客户端程序。

攻击者可以利用 Web shell 作为冗余访问（[Redundant Access](https://attack.mitre.org/techniques/T1108)）和持久性机制，以防万一攻击者的主要访问手段被发现和清除。



## T1084 - Windows Management Instrumentation Event Subscription

## 

## T1004 - Winlogon Helper DLL