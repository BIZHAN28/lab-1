#include "elf_loader.h"
#include "elf_utils.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

int load_elf64(const char *file_path, const char *section_name) {
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        return ENOENT;
    }

    Elf64_Ehdr elf_header;
    if (read_elf_header(fd, &elf_header) != 0) {
        close(fd);
        return EINVAL;
    }

    if (load_program_headers(fd, &elf_header) != 0) {
        close(fd);
        return EIO;
    }

    Elf64_Shdr section_header;
    if (find_section_header(fd, &elf_header, section_name, &section_header) != 0) {
        close(fd);
        return EINVAL;
    }

    if (!(section_header.sh_flags & SHF_EXECINSTR)) {
        close(fd);
        return EINVAL;
    }

    close(fd);

    // Передаем управление на стартовый адрес секции
    void (*entry_point)() = (void (*)())section_header.sh_addr;
    entry_point();

    return 0;
}
