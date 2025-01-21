#ifndef ELF64_LOADER_H
#define ELF64_LOADER_H

#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#define PAGE_SIZE 0x1000

int load_elf64(const char *file, const char *section_name);

#endif
