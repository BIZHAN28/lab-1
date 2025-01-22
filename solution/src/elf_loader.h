#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <elf.h>
#include <stdint.h>

int load_elf64(const char *file_path, const char *section_name);

#endif
