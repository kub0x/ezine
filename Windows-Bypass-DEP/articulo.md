This is the part one of the "Bypassing Windows security mitigations" series. In this article I will cover the protection related to DEP (Data Execution Prevention). When a specified process is hijacked/exploited, if DEP is enabled, the malicious code (shellcode) that resides on stack/heap will not be executed due to DEP marking these as non-executable.

This is the list of requirements being these related to software and user base skills.

|Requirements            |
|------------------------|
|Windows 32 bits      |
|OllyDbg                 |
|Dev-Cpp + GCC compiler*  |
|Basic ASM skills         |
|Patience                 |

*Last version is 5.11 from 2015. This IDE is a nice alternative for Visual Studio for dev in C/C++.

Before going into the rough explanation of how to circumvent this protection, I need to explain that if you run Windows x86 you need to enable PAE first then DEP. In x64 it's enabled by default. So you will wonder, what's PAE? 

PAE stands for Physical Address Execution, is a technique implemented on Windows specially for 32 bit versions that gives the system an improved memory capability that allows the CPU to change the addressing mode to 64 bit, therefore applications can access more than 4GB but will retain their 4GB virtual address space, this will enhance the performance impact on the OS since less paging will be made.

In addition PAE will introduce DEP as a built-in feature. That's why so important to enable PAE if you are running x86 version. No need to worry if you are under x64 version.

