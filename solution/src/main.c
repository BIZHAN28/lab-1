#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define PAGE_SIZE 0x1000

// Function to read the ELF64 header
int read_elf_header(int fd, Elf64_Ehdr *ehdr) {
    if (lseek(fd, 0, SEEK_SET) == -1) {
        return EIO;
    }

    ssize_t bytes_read = read(fd, ehdr, sizeof(Elf64_Ehdr));
    if (bytes_read != sizeof(Elf64_Ehdr)) {
        return EIO;
    }

    if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
        return EINVAL;
    }

    return 0;
}

// Function to load program segments into memory
int load_program_segments(int fd, Elf64_Ehdr *ehdr) {
    Elf64_Phdr phdr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (lseek(fd, ehdr->e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET) == -1) {
            return EIO;
        }

        if (read(fd, &phdr, sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
            return EIO;
        }

        if (phdr.p_type != PT_LOAD) {
            continue; // Only load PT_LOAD segments
        }

        // Adjust the memory size if needed (page size alignment)
        Elf64_Xword aligned_mem_size = (phdr.p_memsz + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
        void *mapped_mem = mmap((void *)phdr.p_vaddr, aligned_mem_size, 
                                (phdr.p_flags & PF_X ? PROT_EXEC : 0) | 
                                (phdr.p_flags & PF_R ? PROT_READ : 0) | 
                                (phdr.p_flags & PF_W ? PROT_WRITE : 0), 
                                MAP_PRIVATE | MAP_FIXED, fd, phdr.p_offset);
        if (mapped_mem == MAP_FAILED) {
            return EIO;
        }
    }

    return 0;
}

// Function to find the section header for the given section name
int find_section_header(int fd, Elf64_Ehdr *ehdr, const char *section_name, Elf64_Shdr *shdr_out) {
    Elf64_Shdr shdr;
    Elf64_Shdr shstrtab_hdr;
    if (lseek(fd, ehdr->e_shoff + ehdr->e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) == -1) {
        return EIO;
    }

    if (read(fd, &shstrtab_hdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
        return EIO;
    }

    char *shstrtab = malloc(shstrtab_hdr.sh_size);
    if (lseek(fd, shstrtab_hdr.sh_offset, SEEK_SET) == -1) {
        free(shstrtab);
        return EIO;
    }

    if (read(fd, shstrtab, shstrtab_hdr.sh_size) != shstrtab_hdr.sh_size) {
        free(shstrtab);
        return EIO;
    }

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (lseek(fd, ehdr->e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET) == -1) {
            free(shstrtab);
            return EIO;
        }

        if (read(fd, &shdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
            free(shstrtab);
            return EIO;
        }

        if (strcmp(&shstrtab[shdr.sh_name], section_name) == 0) {
            *shdr_out = shdr;
            free(shstrtab);
            return 0;
        }
    }

    free(shstrtab);
    return EINVAL;
}

// Function to transfer control to the starting address of the section
void transfer_control(Elf64_Addr entry_point) {
    void (*entry_func)(void) = (void (*)(void)) entry_point;
    entry_func();
}

// Main loader function
int main(int argc, char *argv[]) {
    if (argc != 3) {
        return EINVAL;
    }

    const char *file_name = argv[1];
    const char *section_name = argv[2];

    int fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        return ENOENT;
    }

    Elf64_Ehdr ehdr;
    int err = read_elf_header(fd, &ehdr);
    if (err != 0) {
        close(fd);
        return err;
    }

    err = load_program_segments(fd, &ehdr);
    if (err != 0) {
        close(fd);
        return err;
    }

    Elf64_Shdr target_shdr;
    err = find_section_header(fd, &ehdr, section_name, &target_shdr);
    if (err != 0) {
        close(fd);
        return err;
    }
	if (!(target_shdr.sh_flags & SHF_EXECINSTR)) {
        close(fd);
        return EINVAL;
    }
    transfer_control(target_shdr.sh_addr);
	
    close(fd);


    return 0;
}

