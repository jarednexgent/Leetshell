#include <windows.h>
__attribute__((section(".text"))) unsigned char pMain[] = {
#include "payload.inc" 
};

// undecorated entry symbol name
__declspec(noreturn) void _start(void) {
    ((void(*)())pMain)();   
    ExitProcess(0);             
}