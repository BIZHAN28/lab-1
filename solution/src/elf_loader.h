#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>

/* Macros */
#define PAGE_SIZE 4096
#define ALIGN_DOWN(addr) ((addr) & ~(PAGE_SIZE - 1))
#define ALIGN_UP(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

/* Error handling */
void print_error(const char *msg, int code);

/* ELF operations */
int validate_elf_header(const Elf64_Ehdr *ehdr);
int load_program_segments(int fd, const Elf64_Ehdr *ehdr);
void *find_section(int fd, const Elf64_Ehdr *ehdr, const char *section_name);

#endif /* ELF_LOADER_H */
