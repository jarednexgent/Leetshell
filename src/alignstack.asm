extern Main
global alignstack

section .text
alignstack:
    push rsi
    mov rsi, rsp
    and rsp, -16
    add rsp, -32
    call Main
    lea rsp, [rsi]
    pop rsi
    ret
