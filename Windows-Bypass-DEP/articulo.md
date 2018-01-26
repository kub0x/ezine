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
MOV EAX, [EBP+8] ; pointer to buf
MOV EDX, [EBP-4] ; pointer to tmp
PUSH EAX ; push pointer to buf
PUSH EDX ; push pointer to tmp
CALL strcpy
```

Before calling strcpy, the stack will contain:

|Stack              |
|-------------------|
|tmp_ptr|
|buf_ptr|
|tmp|
|printme_ebp|
|return_address|
|buf_ptr|
|buf|
|main_ebp|
--------------------

As seen before, I've explained what happens when in the stack when executing from the very early until strcpy(). strcpy() will put all the data of buf in tmp, as a consequence if you write more data (bytes) than tmp can't handle an overflow will happen. Here comes the funny part, the last stack view tell us that tmp is above printme_ebp and return_address. These two take 4 bytes each so you only need to overwrite 8 bytes after you fill up tmp with whatever you want.

Let's make a base calculation to know how many bytes to write for triggering an overflow + overwrite of return_address. Note that each memory address is 4 bytes.

tmp has 10 bytes = 2 addresses of 4 bytes full + 2 bytes of a third one -> 12 bytes to fillup, but 2 bytes left and can't leave zeros so -> 14 bytes
printme_ebp - > 4 bytes
return_address -> 4 bytes

Total = 20 bytes

A rule of thumb to follow when calculating how many bytes are needed to overflow + ovewrite the return_address is:

![total_bytes](https://latex.codecogs.com/gif.download?%24nbytes%20%3D%20sizeof%28tmp%29%20%5Cmod%2010%20+%20offset%5C_to%5C_return)

You'd said, nice we know the theory but I'd like a live example. And here it's on C language:

```c
#include <stdio.h>
#include <string.h>

void printme(char *buf){
    char tmp[10];
    strcpy(tmp, buf); // will overflow tmp and smash stack
    printf("%s", tmp);
}

int main (int argc, char **argv){
    char *buf = "XXXXXXXXXXXXXXXXXXXX; // 20 bytes to overwrite return_address
    printme(buf);
    return 0;
}
```
Before printme() returns the stack will look like:

|Stack              |
|-------------------|
|58585858 (4 bytes = 8 hex, 58_h=X)|
|58585858|
|58585858|
|58585858| (printme_ebp)
|58585858 (return_address)|
|buf_ptr|
|buf|
|main_ebp|
--------------------

As seen before 18 bytes are needed to overflow tmp and overwrite return_address. 0x58 is 'X' in hex and equals to 1 byte, each address contains 4 bytes.

