.file "mangle.s"
.intel_syntax noprefix
.section .text
.global PTR_MANGLE
PTR_MANGLE:
    mov rax, QWORD PTR [rdi]
    xor rax, QWORD PTR fs:[0x30] 
    rol rax, 0x11
    mov QWORD PTR [rdi], rax
    xor eax, eax
    ret
