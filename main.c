#include "sha512.h"
#include "sys/stat.h"
#include "assert.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Missing input file.\n");
        return -1;
    }

    u64 registers[8];

    char* path = argv[1];
    struct stat s;
    if (stat(path, &s) == 0) {
        if (s.st_mode & S_IFDIR) {
            printf("Path is a directory - must be a file!\n");
            return -1;
        } else if (!(s.st_mode & S_IFREG)) {
            printf("Unknown path type - must be a file!\n");
            return -1;
        }
    } else {
        printf("Invalid path.\n");
        return -1;
    }

    FILE* stream = fopen(argv[1], "r");
    assert(stream != 0x0);

    sha512(stream, registers);

    fclose(stream);

    printf("SHA512 sum is %llx%llx%llx%llx%llx%llx%llx%llx\n", registers[0], registers[1], registers[2], registers[3], registers[4], registers[5], registers[6], registers[7]);
    
    return 0;
}