#include <stdio.h>

void _start() {

     printf("Hello world\n");

    /* exit system call */
    asm("movl $0, %edi;"
        "movq $60, %rax;"
        "syscall"
    );
}
