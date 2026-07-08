#include <stdio.h>
#include <string.h>

int main(void) {
    char input[128];
    char buffer[8];

    if (fgets(input, sizeof(input), stdin) == NULL) {
        puts("no input");
        return 0;
    }

    strcpy(buffer, input);
    printf("%s", buffer);
    return 0;
}
