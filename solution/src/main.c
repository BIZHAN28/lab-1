#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <errno.h>

#define PAGE_SIZE 0x1000

static int read_elf_header(int fd, Elf64_Ehdr *ehdr) {
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

static int load_program_segments(int fd, Elf64_Ehdr *ehdr) {
    Elf64_Phdr phdr;
    int i;
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (lseek(fd, ehdr->e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET) == -1) {
            return EIO;
        }

        ssize_t bytes_read = read(fd, &phdr, sizeof(Elf64_Phdr));
        if (bytes_read != sizeof(Elf64_Phdr)) {
            return EIO;
        }

        if (phdr.p_type != PT_LOAD) {
            continue;
        }

        long page_size = sysconf(_SC_PAGE_SIZE);
        if (page_size <= 0) {
            return EIO;
        }

        Elf64_Addr aligned_vaddr = phdr.p_vaddr & ~(page_size - 1);
        Elf64_Off aligned_offset = phdr.p_offset & ~(page_size - 1);
        Elf64_Xword aligned_mem_size = phdr.p_memsz + (phdr.p_vaddr - aligned_vaddr);

        void *mapped_mem = mmap((void *)aligned_vaddr, aligned_mem_size,
                                (phdr.p_flags & PF_X ? PROT_EXEC : 0) |
                                (phdr.p_flags & PF_R ? PROT_READ : 0) |
                                (phdr.p_flags & PF_W ? PROT_WRITE : 0),
                                MAP_PRIVATE | MAP_FIXED, fd, aligned_offset);

        if (mapped_mem == MAP_FAILED) {
            return EIO;
        }
    }

    return 0;
}

static int find_section_header(int fd, Elf64_Ehdr *ehdr, const char *section_name, Elf64_Shdr *shdr_out) {
    Elf64_Shdr shdr;
    Elf64_Shdr shstrtab_hdr;
    char shstrtab[PAGE_SIZE];
    int i;

    if (lseek(fd, ehdr->e_shoff + ehdr->e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) == -1) {
        return EIO;
    }

    ssize_t bytes_read = read(fd, &shstrtab_hdr, sizeof(Elf64_Shdr));
    if (bytes_read != sizeof(Elf64_Shdr)) {
        return EIO;
    }

    if (shstrtab_hdr.sh_size > PAGE_SIZE) {
        return EIO;
    }

    if (lseek(fd, shstrtab_hdr.sh_offset, SEEK_SET) == -1) {
        return EIO;
    }

    bytes_read = read(fd, shstrtab, shstrtab_hdr.sh_size);
    if (bytes_read != shstrtab_hdr.sh_size) {
        return EIO;
    }

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (lseek(fd, ehdr->e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET) == -1) {
            return EIO;
        }

        bytes_read = read(fd, &shdr, sizeof(Elf64_Shdr));
        if (bytes_read != sizeof(Elf64_Shdr)) {
            return EIO;
        }

        int j = 0;
        while (section_name[j] != '\0' && shstrtab[shdr.sh_name + j] == section_name[j]) {
            j++;
        }

        if (section_name[j] == '\0' && shstrtab[shdr.sh_name + j] == '\0') {
            *shdr_out = shdr;
            return 0;
        }
    }

    return EINVAL;
}

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

    void (*entry_func)(void) = (void (*)(void)) target_shdr.sh_addr;
    if (entry_func == NULL) {
        close(fd);
        return EINVAL;
    }

    entry_func();

    close(fd);
    return 0;
}
