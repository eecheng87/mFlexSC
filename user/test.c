#include <stdio.h>
#include <sys/syscall.h> /* For SYS_xxx definitions */
#include <unistd.h>

int main() {
    /* Testing for system call hooked by kernel module */
    syscall(400);
    syscall(401);
    return 0;
}
