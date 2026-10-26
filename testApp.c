#include <stdio.h>
#include <windows.h>

int main(int argc, char** argv) {
    (void)argv;
    
    if (argc > 1) {
        printf("This program doesn't require anything!\n");

        return -1;
    }

    printf("This Program's PID: %lu\n", GetCurrentProcessId());

    getchar();

    return 0;
}