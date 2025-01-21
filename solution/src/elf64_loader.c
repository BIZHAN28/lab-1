#include "elf64_loader.h"

static void *align_down(void *addr, size_t alignment) {
    return (void *)((uintptr_t)addr & ~(alignment - 1));
}

static void *align_up(void *addr, size_t alignment) {
    return (void *)(((uintptr_t)addr + alignment - 1) & ~(alignment - 1));
}

int load_elf64(const char *file, const char *section_name) {
    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        return ENOENT;
    }

    // Читаем ELF-заголовок
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return EIO;
    }

    // Проверяем magic number
    if (ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F') {
        close(fd);
        return EINVAL;
    }

    // Загружаем программные сегменты
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (lseek(fd, ehdr.e_phoff + i * sizeof(phdr), SEEK_SET) < 0 ||
            read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
            close(fd);
            return EIO;
        }

        if (phdr.p_type != PT_LOAD) {
            continue; // Загружаем только PT_LOAD
        }

        // Выравниваем адрес
        void *aligned_addr = align_down((void *)phdr.p_vaddr, PAGE_SIZE);
        size_t mem_size = (size_t)((char *)align_up((void *)(phdr.p_vaddr + phdr.p_memsz), PAGE_SIZE) - (char *)aligned_addr);

        // Маппинг памяти
        void *mapped = mmap(aligned_addr, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (mapped == MAP_FAILED) {
            close(fd);
            return ENOMEM;
        }

        // Чтение данных в память
        if (lseek(fd, phdr.p_offset, SEEK_SET) < 0 ||
            read(fd, (void *)phdr.p_vaddr, phdr.p_filesz) != (ssize_t)phdr.p_filesz) {
            munmap(mapped, mem_size);
            close(fd);
            return EIO;
        }

        // Установка прав доступа
        if (mprotect(mapped, mem_size, phdr.p_flags) < 0) {
            munmap(mapped, mem_size);
            close(fd);
            return EPERM;
        }
    }

    // Ищем указанную секцию
    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        if (lseek(fd, ehdr.e_shoff + i * sizeof(shdr), SEEK_SET) < 0 ||
            read(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) {
            close(fd);
            return EIO;
        }

        // Проверка имени секции
        if (shdr.sh_name == 0 || !(shdr.sh_flags & SHF_EXECINSTR)) {
            continue;
        }

        // Передача управления на sh_addr
        void (*entry_point)(void) = (void (*)(void))(shdr.sh_addr);
        close(fd);
        entry_point();
        return 0;
    }

    close(fd);
    return EINVAL; // Секция не найдена
}
