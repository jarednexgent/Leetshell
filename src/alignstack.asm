extern Main                ; Reference to the external function in leetshell.c

global alignstack          ; Mark alignstack as the entry point for the linker

segment .text              ; Start of the .text section (code segment)

alignstack:
    push rdi               ; Save rdi to preserve its original value
    mov rdi, rsp           ; Backup current stack pointer to rdi
    and rsp, byte -0x10    ; Align stack to 16-byte boundary (required by Windows x64 calling convention)
    sub rsp, byte +0x20    ; Reserve 32 bytes of shadow space for called C function
    call Main              ; Call the C function
    mov rsp, rdi           ; Restore original stack pointer
    pop rdi                ; Restore rdi
    ret                    ; Return to caller