#include <Windows.h>

#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBeep(0xFFFFFFFF);
        MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "", MB_OK);
        break;

    case DLL_THREAD_ATTACH:
        MessageBeep(0xFFFFFFFF);
        MessageBoxA(NULL, "DLL_THREAD_ATTACH", "", MB_OK);
        break;

    case DLL_THREAD_DETACH:
        MessageBeep(0xFFFFFFFF);
        MessageBoxA(NULL, "DLL_THREAD_DETACH", "", MB_OK);
        break;

    case DLL_PROCESS_DETACH:
        MessageBeep(0xFFFFFFFF);
        MessageBoxA(NULL, "DLL_PROCESS_DETACH", "", MB_OK);
        break;
    }

    return TRUE;
}

