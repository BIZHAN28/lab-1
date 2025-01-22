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
