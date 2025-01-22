#include "elf_utils.h"
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

int read_elf_header(int fd, Elf64_Ehdr *header) {
    if (lseek(fd, 0, SEEK_SET) < 0) {
        return EIO;
    }

    if (read(fd, header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        return EIO;
    }

    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        return EINVAL;
    }

    return 0;
}

int load_program_headers(int fd, const Elf64_Ehdr *header) {
    for (int i = 0; i < header->e_phnum; i++) {
        Elf64_Phdr phdr;

        if (lseek(fd, header->e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET) < 0) {
            return EIO;
        }

        if (read(fd, &phdr, sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
            return EIO;
        }

        if (phdr.p_type == PT_LOAD) {
            void *mem = mmap((void *)(phdr.p_vaddr & ~(0xFFF)), 
                             phdr.p_memsz + (phdr.p_vaddr & 0xFFF),
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS,
                             -1, 0);
                             
            if (mem == MAP_FAILED) {
                return ENOMEM;
            }

            if (lseek(fd, phdr.p_offset, SEEK_SET) < 0 || 
                read(fd, mem + (phdr.p_vaddr & 0xFFF), phdr.p_filesz) != phdr.p_filesz) {
                return EIO;
            }

            if (mprotect(mem, phdr.p_memsz, PROT_READ | PROT_EXEC) != 0) {
                return EIO;
            }
        }
    }

    return 0;
}

int find_section_header(int fd, const Elf64_Ehdr *header, const char *section_name, Elf64_Shdr *section_header) {
    Elf64_Shdr shstrtab_header;

    if (lseek(fd, header->e_shoff + header->e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) < 0 ||
        read(fd, &shstrtab_header, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
        return EIO;
    }

    char *shstrtab = mmap(NULL, shstrtab_header.sh_size, PROT_READ, MAP_PRIVATE, fd, shstrtab_header.sh_offset);
    if (shstrtab == MAP_FAILED) {
        return ENOMEM;
    }

    for (int i = 0; i < header->e_shnum; i++) {
        if (lseek(fd, header->e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET) < 0 ||
            read(fd, section_header, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
            munmap(shstrtab, shstrtab_header.sh_size);
            return EIO;
        }

        const char *current_name = shstrtab + section_header->sh_name;
        if (strcmp(current_name, section_name) == 0) {
            munmap(shstrtab, shstrtab_header.sh_size);
            return 0;
        }
    }

    munmap(shstrtab, shstrtab_header.sh_size);
    return EINVAL;
}
