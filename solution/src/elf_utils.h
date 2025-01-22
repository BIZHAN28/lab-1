#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <stdint.h>
#include <unistd.h>

int read_elf_header(int fd, Elf64_Ehdr *header);
int find_section_header(int fd, const Elf64_Ehdr *header, const char *section_name, Elf64_Shdr *section_header);
int load_program_headers(int fd, const Elf64_Ehdr *header);

#endif
