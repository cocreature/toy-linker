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

void extern_call() {
    print(1, "wuhu\n", 5);
}
