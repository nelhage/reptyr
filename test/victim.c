#include <stdio.h>

int main(int argc, char **argv) {
    char *line = NULL;
    size_t cap = 0;

    while(getline(&line, &cap, stdin) != -1) {
        printf("ECHO: %s", line);
    }

    return 0;
}
