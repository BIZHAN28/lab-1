// File: solution/src/elf_loader.c
// Header inclusion
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include "elf_loader.h"

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN_DOWN(addr) ((addr) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

// Error output helper
void error(const char *msg, int code) {
    write(2, msg, strlen(msg));
    exit(code);
}

// Function to read data from file descriptor
ssize_t read_data(int fd, void *buf, size_t size, off_t offset) {
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
        return -1;
    }
    return read(fd, buf, size);
}

// Load program headers into memory
void load_segments(int fd, const Elf64_Ehdr *ehdr) {
    Elf64_Phdr phdr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (read_data(fd, &phdr, sizeof(phdr), ehdr->e_phoff + i * sizeof(phdr)) != sizeof(phdr)) {
            error("Failed to read program header\n", EIO);
        }

        if (phdr.p_type != PT_LOAD) {
            continue;
        }

        // Align memory range
        off_t file_offset = PAGE_ALIGN_DOWN(phdr.p_offset);
        size_t mem_size = PAGE_ALIGN_UP(phdr.p_vaddr + phdr.p_memsz) - PAGE_ALIGN_DOWN(phdr.p_vaddr);

        // Map memory
        void *mapped = mmap((void *)PAGE_ALIGN_DOWN(phdr.p_vaddr), mem_size, PROT_READ | PROT_WRITE | PROT_EXEC, 
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (mapped == MAP_FAILED) {
            error("Failed to allocate memory for segment\n", ENOMEM);
        }

        // Load segment data
        if (read_data(fd, mapped, phdr.p_filesz, file_offset) != (ssize_t)phdr.p_filesz) {
            error("Failed to load segment data\n", EIO);
        }

        // Set memory protection
        int prot = 0;
        if (phdr.p_flags & PF_R) prot |= PROT_READ;
        if (phdr.p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr.p_flags & PF_X) prot |= PROT_EXEC;
        if (mprotect(mapped, mem_size, prot) != 0) {
            error("Failed to set memory protection\n", EIO);
        }
    }
}

// Locate and validate the section
Elf64_Addr locate_section(int fd, const Elf64_Ehdr *ehdr, const char *section_name) {
    Elf64_Shdr shdr;
    char *strtab;

    // Read section string table
    if (read_data(fd, &shdr, sizeof(shdr), ehdr->e_shoff + ehdr->e_shstrndx * sizeof(shdr)) != sizeof(shdr)) {
        error("Failed to read section header\n", EIO);
    }

    strtab = malloc(shdr.sh_size);
    if (!strtab) {
        error("Failed to allocate memory for string table\n", ENOMEM);
    }

    if (read_data(fd, strtab, shdr.sh_size, shdr.sh_offset) != (ssize_t)shdr.sh_size) {
        error("Failed to read string table\n", EIO);
    }

    // Find the section
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (read_data(fd, &shdr, sizeof(shdr), ehdr->e_shoff + i * sizeof(shdr)) != sizeof(shdr)) {
            free(strtab);
            error("Failed to read section header\n", EIO);
        }

        if (strcmp(&strtab[shdr.sh_name], section_name) == 0) {
            if (!(shdr.sh_flags & SHF_EXECINSTR)) {
                free(strtab);
                error("Section is not executable\n", EINVAL);
            }
            free(strtab);
            return shdr.sh_addr;
        }
    }

    free(strtab);
    error("Section not found\n", EINVAL);
    return 0; // Should never reach here
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 3) {
        error("Usage: ./elf64-loader <source-elf64-file> <section-name>\n", EINVAL);
    }

    const char *filename = argv[1];
    const char *section_name = argv[2];

    // Open ELF file
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        error("Failed to open file\n", ENOENT);
    }

    // Read ELF header
    Elf64_Ehdr ehdr;
    if (read_data(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
        close(fd);
        error("Failed to read ELF header\n", EIO);
    }

    // Validate ELF magic number
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        close(fd);
        error("Invalid ELF file\n", EINVAL);
    }

    // Load segments into memory
    load_segments(fd, &ehdr);

    // Locate the target section
    Elf64_Addr section_addr = locate_section(fd, &ehdr, section_name);

    // Close file descriptor
    close(fd);

    // Transfer control to the section
    void (*entry_point)(void) = (void (*)(void))section_addr;
    entry_point();

    return 0;
}
