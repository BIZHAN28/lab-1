#include "elf_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        write(2, "Usage: ./elf64-loader <source-elf64-file> <section-name>\n", 56);
        return EINVAL;
    }

    const char *file_path = argv[1];
    const char *section_name = argv[2];

    int result = load_elf64(file_path, section_name);
    if (result != 0) {
        char error_msg[64];
        int len = snprintf(error_msg, sizeof(error_msg), "Error: %d\n", result);
        write(2, error_msg, len);
        return result;
    }

    return 0;
}
