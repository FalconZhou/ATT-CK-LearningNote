[TOC]

# TA0003 - 持续化 Persistence
## T1156 - .bash_profile and .bashrc

`~/.bash_profile` and `~/.bashrc` are shell scripts that contain shell commands. These files are executed in a user's context when a new shell opens or when a user logs in so that their environment is set correctly. `~/.bash_profile` is executed for login shells and `~/.bashrc` is executed for interactive non-login shells. This means that when a user logs in (via username and password) to the console (either locally or remotely via something like SSH), the `~/.bash_profile` script is executed before the initial command prompt is returned to the user. After that, every time a new shell is opened, the `~/.bashrc` script is executed. This allows users more fine-grained control over when they want certain commands executed. These shell scripts are meant to be written to by the local user to configure their own environment.


## T1015 - 辅助功能 Accessibility Features
Windows contains accessibility features that may be launched with a key combination before a user has logged in (for example, when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.


## T1098 - 账户操作 Account Manipulation
Account manipulation may aid adversaries in maintaining access to credentials and certain permission levels within an environment. Manipulation could consist of modifying permissions, modifying credentials, adding or changing permission groups, modifying account settings, or modifying how authentication is performed. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to subvert password duration policies and preserve the life of compromised credentials. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.


## T1182 - AppCert DLLs注册表


Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session` Manager are loaded into every process that calls the ubiquitously used application programming interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec.

## T1103 - AppInit DLLs

Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry keys `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows` or `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows` are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. Similar to Process Injection, these values can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.


## T1138 - Application Shimming

The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10. Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses Hooking to redirect the code as necessary in order to communicate with the OS.

## T1131 - Authentication Package

Windows Authentication Package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.


## T1197 - BITS Jobs
Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.


## T1067 - Booktkit
A bootkit is a malware variant that modifies the boot sectors of a hard drive, including the Master Boot Record (MBR) and Volume Boot Record (VBR).


## T1176 - Browser Extensions


## T1042 - Change Default File Association


## T1109 - Component Firmware


## T1122 - Componet Object Model Hijacking


## T1136 - Create Account


## T1038 - DLL Search Order Hijacking


## T1157 - Dylib Hijacking


## T1519 - Emond


## T1133 - External Remote Services


## T1044 - File System Permissions Weakness


## T1158 - Hidden Files and Directories


## T1179 - Hooking


## T1062 - Hypervisor


## T1183 - Image File Execution Options Injection


## T1525 - Implant Container Image


## T1215 - Kernel Modules and Extensions


## T1159 - Launch Agent


## T1160 - Launch Daemon


## T1152 - Launchctl


## T1161 - LC_LOAD_DYLIB Addition


## T1168 - Local Job Scheduling


## T1162 - Login Item



## T1037 - Logon Scripts


## T1177 - LSASS Driver


## T1031 - Modify Existing Service


## T1128 - Netsh Helper DLL



## T1050 - New Service


## T1137 - Office Application Startup


## T1034 - Path Interception


## T1150 - Plist Modification


## T1205 - Port Knocking


## T1013 - Port Monitors


## T1504 - PowerShell Profile


## T1163 - Rc.common


## T1164 - Re-opend Applications


## T1108 - Redundant Access


## T1060 - Registry Run Keys / Startup Folder


## T1053 - Scheduled Task


## T1180 - Screensaver


## T1101 - Security Support Provider


## T1505 - Server Software Component


## T1058 - Service Registry Permissions Weakness


## T1166 - Setuid and Setgid


## T1023 - Shortcut Modification


## T1198 - SIP and Trust Provider Hijacking


## T1165 - Startup Items


## T1019 - System Firmware


## T1501 - Systemd Service


## T1209 - Time Providers


## T1154 - Trap


## T1078 - Valid Accounts


## T1100 - Web Shell


## T1084 - Windows Management Instrumentation Event Subscription


## T1004 - Winlogon Helper DLL