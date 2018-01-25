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

Now I will enumerate the questions that I'll be answering further so you can make an idea about what will be covered:

What vulnerability do I use to exploit and run code?

How do I trigger DEP to block the execution of code?

How do I execute code if DEP is enabled and blocking my own code (shellcode)?

What is a ROP Chain?

How do other protections affect DEP impact on security?

Do I need to disable other protection(s)?

How do I use a Debugger to create a reliable exploit and spawn my shellcode?

All is said so let's start answering these questions one by one.

What vulnerability do I use to exploit and run code?

In this context I'm using a Buffer Overflow to smash the stack in order to overwrite the return address. When the program returns it will jump to what its there, normally to the previous function (in a correct behaviour).
The point here is to achieve that the program returns to our function, and this will spawn whatever we are interested on (i.e: a cmd, bind/reverse tcp...).

Imagine this basic scenario: you've declared a string on the main function of your program and you want to print it through printme() function. printme() will copy our string to a temp buffer then print it.

```c
#include <stdio.h>
#include <string.h>

void printme(char *buf){
    char tmp[10];
    strcpy(tmp, buf);
    printf("%s", tmp);
}

int main (int argc, char **argv){
    char *buf = "Hello World!\n";
    printme(buf);
    return 0;
}
```

Before printme(buf) the stack can be viewed as:

|Stack              |
|-------------------|
|buf|
|main_ebp|

When printme(buf) is reached it will perform a:

```nasm
PUSH ESP ; will put buf pointer onto stack, param for strcpy
CALL printme ; save return address and transfer EIP there
```

When the call to printme() is made, it will begin with the function prologe. Just save old EBP, setup a new stack frame and point EBP to this new value:

```nasm
printme:

PUSH EBP
MOV EBP, ESP
SUB ESP, 0xA ; Allocate 10 bytes for tmp string
```

From the stack view we will have:

|Stack              |
|-------------------|
|tmp|
|printme_ebp|
|return_address|
|buf_ptr|
|buf|
|main_ebp|
...




