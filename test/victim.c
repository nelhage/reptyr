#include <stdio.h>
#include <sys/prctl.h>

int main(int argc, char **argv) {
    char *line = NULL;
    size_t cap = 0;

    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);

    while(getline(&line, &cap, stdin) != -1) {
        printf("ECHO: %s", line);
    }

    return 0;
}
