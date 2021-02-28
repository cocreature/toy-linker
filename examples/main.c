#include <stddef.h>

static void print(int fd, const void* buf, size_t count) {
    asm("movq $1, %%rax;"
        "movl %[fd], %%edi;"
        "movq %[buf], %%rsi;"
        "movq %[count], %%rdx;"
        "syscall"
        :
        : [fd] "r" (fd), [buf] "r" (buf), [count] "r" (count)
    );
}

static int main() {
    const char* str = "Hello world\n";
    print(1, str, 12);
    return 42;
}

 void _start() {

    int exit = main();

    /* exit system call */
    asm("movl %0, %%edi;"
        "movq $60, %%rax;"
        "syscall"
        :
        : "r" (exit)
    );
}
