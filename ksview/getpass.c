#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>


int password_get(char *pass, size_t size)
{
    struct termios flags, nflags;

    tcgetattr(STDIN_FILENO, &flags);
    nflags = flags;
    nflags.c_lflag = (nflags.c_lflag & ~ECHO) | ECHONL;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &nflags) != 0) {
        perror("tcsetattr");
        return -1;
    }

    printf("Password: ");

    if (!fgets(pass, size, stdin)) {
        perror("fgets");
        return -1;
    }

    pass[size - 1] = 0;

    for (size_t at = strlen(pass); at > 0; at--) {
        if (pass[at - 1] != '\n')
            break;
        pass[at - 1] = 0;
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &flags) != 0) {
        perror("tcsetattr");
        return -1;
    }

    return 0;
}
