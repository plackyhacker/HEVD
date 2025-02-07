# HackSys Extreme Vulnerable Driver Exploits

<img width="339" alt="Screenshot 2023-06-22 at 19 18 49" src="https://github.com/plackyhacker/HEVD/assets/42491100/f479cecd-4bb0-4004-a717-812f71ef082e">

My attempts at kernel exploitation on the purposely vulnerable driver, HEVD.

# Windows 2022

## Double Fetch

A double fetch bug occurs when a kernel or privileged code fetches the same memory value twice, allowing attackers to exploit race conditions and manipulate data between the two reads. 

[Double Fetch - Windows 2022 10.0.20348 N/A Build 20348](https://github.com/plackyhacker/HEVD/blob/main/windows-2022/double-fetch/double_fetch.cpp)

[Shellcode](https://github.com/plackyhacker/HEVD/blob/main/windows-2022/double-fetch/double_fetch_shellcode.asm)

## Type Confusion

Type confusion refers to a vulnerability where a program assumes a specific data type for an object, but due to a flaw, the object's type is manipulated or misinterpreted. This can lead to unpredictable behavior, allowing attackers to manipulate memory and potentially execute arbitrary code.

[Type Confusion - Windows 2022 10.0.20348 N/A Build 20348](https://github.com/plackyhacker/HEVD/blob/main/windows-2022/type-confusion/type_confusion.cpp)

[Type Confusion - Windows 7 64bit SP1](https://github.com/plackyhacker/HEVD/blob/main/hevd_type_confusion.cpp)

# Windows 10

## Stack Based Buffer Overflow

A stack-based buffer overflow occurs when a program writes more data into a buffer on the stack than its allocated size, potentially overwriting adjacent memory and allowing for unauthorised code execution or system crashes. I also used this as an opportunity to bypass SMEP in Windows 10 using a short ROP chain.

[Stack-based Buffer Overflow - Windows 10 64bit 1607](https://github.com/plackyhacker/HEVD/blob/main/hevd_stack_overflow.cpp)

# Windows 7

## Null Pointer Dereference

Null pointer dereference occurs when a program attempts to access or manipulate memory through a null pointer, leading to unexpected behavior or crashes. This is a fairly easy exploit but is not available on newer versions of Windows.

[Null Pointer Dereference - Windows 7 64bit SP1](https://github.com/plackyhacker/HEVD/blob/main/hevd_null_pointer_deref.cpp)

## Arbitrary Write

Arbitrary write is a vulnerability that occurs when an attacker is able to write data to an arbitrary memory location. This can lead to unauthorized modification of critical data, specifically control flow hijacking. This is also referred to as a Write, What, Where vulnerability. This is a really interesting exploit as I used the HalDispatchTable in the kernel to get code execution in kernel mode from user mode.

[Arbitrary Write - Windows 7 64bit SP1](https://github.com/plackyhacker/HEVD/blob/main/hevd_arbitrary_write.cpp)

## Integer Overflow

Integer overflow refers to the situation where the result of an arithmetic operation on integers exceeds the maximum representable value for the given data type. This can lead to security vulnerabilities if not properly handled. Attackers can exploit integer overflows to bypass security checks, and cause arbitrary code execution; as in this exploit.

[Integer Overflow - Windows 7 32bit SP1](https://github.com/plackyhacker/HEVD/blob/main/hevd_integer_overflow.cpp)

I made a modification to my original exploit, to test (and for fun) a condition where I was unable to restore execution in the kernel, so instead I let the code loop indefinitely. I apply the elevated token to a seperate process first.

[Integer Overflow v2 - Windows 7 32bit SP1](https://github.com/plackyhacker/HEVD/blob/main/hevd_integer_overflow_spin.cpp)
