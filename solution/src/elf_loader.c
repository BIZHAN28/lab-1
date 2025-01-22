#include "../include/elf_loader.h"

/* Prints error messages to stderr and exits with the given code */
void print_error(const char *msg, int code) {
    write(2, msg, strlen(msg));
    write(2, "\n", 1);
    exit(code);
}

/* Validates ELF header */
int validate_elf_header(const Elf64_Ehdr *ehdr) {
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return 0; // Invalid ELF magic
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return 0; // Not an ELF64 file
    }
    return 1;
}

/* Loads program segments (PT_LOAD) into memory */
int load_program_segments(int fd, const Elf64_Ehdr *ehdr) {
    if (lseek(fd, ehdr->e_phoff, SEEK_SET) == -1) {
        print_error("Failed to seek program headers", EIO);
    }

    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr phdr;
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
            print_error("Failed to read program header", EIO);
        }

        if (phdr.p_type == PT_LOAD) {
            size_t mem_size = ALIGN_UP(phdr.p_memsz);
            size_t file_size = phdr.p_filesz;

            void *mapped = mmap((void *)ALIGN_DOWN(phdr.p_vaddr),
                                mem_size,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS,
                                -1,
                                0);
            if (mapped == MAP_FAILED) {
                print_error("Memory mapping failed", EIO);
            }

            if (lseek(fd, phdr.p_offset, SEEK_SET) == -1) {
                print_error("Failed to seek to segment data", EIO);
            }

            if (read(fd, mapped, file_size) != file_size) {
                print_error("Failed to read segment data", EIO);
            }

            if (mprotect(mapped, mem_size, phdr.p_flags & (PROT_READ | PROT_WRITE | PROT_EXEC)) == -1) {
                print_error("Failed to set memory protections", EIO);
            }
        }
    }

    return 0;
}

/* Finds and validates the section */
void *find_section(int fd, const Elf64_Ehdr *ehdr, const char *section_name) {
    if (lseek(fd, ehdr->e_shoff, SEEK_SET) == -1) {
        print_error("Failed to seek section headers", EIO);
    }

    Elf64_Shdr shdr;
    Elf64_Shdr shstrtab_hdr;

    // Seek to section string table
    if (lseek(fd, ehdr->e_shoff + (ehdr->e_shstrndx * sizeof(Elf64_Shdr)), SEEK_SET) == -1) {
        print_error("Failed to seek section string table header", EIO);
    }

    if (read(fd, &shstrtab_hdr, sizeof(shstrtab_hdr)) != sizeof(shstrtab_hdr)) {
        print_error("Failed to read section string table header", EIO);
    }

    // Read section name string table
    char *section_names = malloc(shstrtab_hdr.sh_size);
    if (!section_names) {
        print_error("Failed to allocate memory for section names", ENOMEM);
    }

    if (lseek(fd, shstrtab_hdr.sh_offset, SEEK_SET) == -1) {
        print_error("Failed to seek to section name string table", EIO);
    }

    if (read(fd, section_names, shstrtab_hdr.sh_size) != shstrtab_hdr.sh_size) {
        free(section_names);
        print_error("Failed to read section name string table", EIO);
    }

    // Locate the desired section
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (lseek(fd, ehdr->e_shoff + (i * sizeof(Elf64_Shdr)), SEEK_SET) == -1) {
            free(section_names);
            print_error("Failed to seek section header", EIO);
        }

        if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) {
            free(section_names);
            print_error("Failed to read section header", EIO);
        }

        if (strcmp(section_name, section_names + shdr.sh_name) == 0) {
            free(section_names);
            if (!(shdr.sh_flags & SHF_EXECINSTR)) {
                print_error("Section is not executable", EINVAL);
            }
            return (void *)shdr.sh_addr;
        }
    }

    free(section_names);
    print_error("Section not found", EINVAL);
    return NULL; // Unreachable, to suppress warnings
}

/* Entry point */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        print_error("Usage: ./elf64-loader <source-elf64-file> <section-name>", EINVAL);
    }

    const char *filename = argv[1];
    const char *section_name = argv[2];

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        print_error("Failed to open file", ENOENT);
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        print_error("Failed to read ELF header", EIO);
    }

    if (!validate_elf_header(&ehdr)) {
        close(fd);
        print_error("Invalid ELF64 file", EINVAL);
    }

    load_program_segments(fd, &ehdr);

    void *section_address = find_section(fd, &ehdr, section_name);

    close(fd);

    // Transfer control
    void (*entry_point)(void) = section_address;
    entry_point();

    return 0;
}
