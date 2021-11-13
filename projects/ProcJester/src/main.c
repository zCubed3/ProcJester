#include <stdio.h>
#include <stdint.h>

#include <Windows.h>
#include <psapi.h>

// Based on: http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html

const char* dllToInject;

#define MAX_HISTORY 512
uint32_t previousPIds[MAX_HISTORY];
int pIdIndex = 0;

void 
InjectToProcess(uint32_t procId) {
    printf("[Injection] Calling OpenProcess() for PID %i...\n", procId);

    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ,
        FALSE,
        procId
    );

    if (hProc == NULL) {
        printf("[Injection] Failed to get a valid HANDLE! Injection failed but will try again!");
        return;
    }
    else {
        printf("[Injection] Got HANDLE, 0x%p\n", hProc);
    }

    void* dllPathAddr = VirtualAllocEx(hProc, 0, strlen(dllToInject), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    BOOL wrote = WriteProcessMemory(hProc, dllPathAddr, dllToInject, strlen(dllToInject), NULL);
    
    printf("[Injection] Wrote DLL path into process memory space...\n");

    void* loadLibAddr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");

    printf("[Injection] Invoking LoadLibraryA() within process memory space...\n");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibAddr, dllPathAddr, NULL, NULL);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hProc);

    previousPIds[pIdIndex++] = procId;

    if (pIdIndex >= MAX_HISTORY)
        pIdIndex = 0;
}

void
AttachToProcessesOfName(const char* name) {
    DWORD pIds[2048], idsNeeded;
    
    if (!EnumProcesses(pIds, sizeof(pIds), &idsNeeded)) {
        return;
    }

    DWORD foundIds = idsNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < foundIds; i++) {
        if (pIds[i] != 0) {
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION |
                PROCESS_VM_READ,
                FALSE,
                pIds[i]
            );

            if (hProc == NULL)
                continue;

            char procName[MAX_PATH];
            GetModuleFileNameEx(hProc, NULL, procName, sizeof(procName));

            if (strstr(procName, name)) {
                for (uint32_t p = 0; p < MAX_HISTORY; p++)
                    if (pIds[i] == previousPIds[p])
                        return;

                printf("===== INJECTION =====\n");
                printf("PID: %u\nExecutable: %s\n", pIds[i], procName);
                printf("\nLog:\n");
                InjectToProcess(pIds[i]);
                printf("=====================\n");
            }

            CloseHandle(hProc);
        }
    }
}

int 
main(int argc, char** argv) {
    if (argc < 3) {
        printf("Please provide the executable name and path to the dll!\nEx: ProcJester.exe SomeGame.exe \"C:\\SomeModMenu.dll\"\n");
        return 1;
    }

    BOOL closeAfterFirstIteration = 0;
    if (argc >= 4) {
        if (strcmp(argv[3], "TRUE") == 0) {
            closeAfterFirstIteration = 1;
            printf("Will close automatically after first iteration!\n");
        }
    }

    char* name = argv[1];
    dllToInject = argv[2];
    printf("Looking for exe's with names containing '%s'\nInjecting %s\n\n", argv[1], dllToInject);

    while (1) {
        AttachToProcessesOfName(name);

        if (closeAfterFirstIteration)
            break;

        //Sleep(7500);
        printf("\nPress enter to look for processes again...\n");
        getchar();
    }
}