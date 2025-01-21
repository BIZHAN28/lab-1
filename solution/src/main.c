#include "elf64_loader.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        return EINVAL;
    }

    const char *file = argv[1];
    const char *section_name = argv[2];

    return load_elf64(file, section_name);
}
