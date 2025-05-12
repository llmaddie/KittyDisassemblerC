#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <capstone/capstone.h>
#include <ctype.h>

typedef struct {
    int show_sections;    // -h
    int show_symbols;     // -t
    int disassemble;      // -d
    int show_header;      // -f
    int show_relocs;      // -r
    int show_dyn_relocs;  // -R
    int show_hex;         // -x
    char *filename;
} options_t;

void parse_args(int argc, char **argv, options_t *opts) {
    memset(opts, 0, sizeof(options_t));
    opts->filename = "/bin/ls"; // Default

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (char *p = &argv[i][1]; *p; p++) {
                switch (*p) {
                    case 'h': opts->show_sections = 1; break;
                    case 't': opts->show_symbols = 1; break;
                    case 'd': opts->disassemble = 1; break;
                    case 'f': opts->show_header = 1; break;
                    case 'r': opts->show_relocs = 1; break;
                    case 'R': opts->show_dyn_relocs = 1; break;
                    case 'x': opts->show_hex = 1; break;
                }
            }
        } else {
            opts->filename = argv[i];
        }
    }
}

const char *get_section_type(uint32_t type) {
    switch(type) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_STRTAB: return "STRTAB";
        case SHT_RELA: return "RELA";
        case SHT_NOBITS: return "NOBITS";
        case SHT_REL: return "REL";
        case SHT_DYNSYM: return "DYNSYM";
        default: return "UNKNOWN";
    }
}

const char *get_reloc_type(uint32_t type) {
    switch(type) {
        case R_X86_64_64: return "R_X86_64_64";
        case R_X86_64_PC32: return "R_X86_64_PC32";
        case R_X86_64_GOT32: return "R_X86_64_GOT32";
        case R_X86_64_PLT32: return "R_X86_64_PLT32";
        case R_X86_64_COPY: return "R_X86_64_COPY";
        case R_X86_64_GLOB_DAT: return "R_X86_64_GLOB_DAT";
        case R_X86_64_JUMP_SLOT: return "R_X86_64_JUMP_SLOT";
        case R_X86_64_RELATIVE: return "R_X86_64_RELATIVE";
        case R_X86_64_DTPMOD64: return "R_X86_64_DTPMOD64";
        case R_X86_64_DTPOFF64: return "R_X86_64_DTPOFF64";
        case R_X86_64_TPOFF64: return "R_X86_64_TPOFF64";
        default: return "UNKNOWN";
    }
}

void show_elf_header(Elf64_Ehdr *ehdr) {
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) printf("%02x ", ehdr->e_ident[i]);
    printf("\n");
    
    printf("  Class:                             %s\n", 
           ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64" : "ELF32");
    printf("  Data:                              %s\n",
           ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "2's complement, little endian" : "2's complement, big endian");
    printf("  Version:                           %d (current)\n", ehdr->e_ident[EI_VERSION]);
    printf("  OS/ABI:                            %s\n",
           ehdr->e_ident[EI_OSABI] == ELFOSABI_LINUX ? "UNIX - Linux" : "Other");
    printf("  ABI Version:                       %d\n", ehdr->e_ident[EI_ABIVERSION]);
    printf("  Type:                              %s\n",
           ehdr->e_type == ET_EXEC ? "EXEC (Executable file)" :
           ehdr->e_type == ET_DYN ? "DYN (Shared object file)" : "Other");
    printf("  Machine:                           %s\n",
           ehdr->e_machine == EM_X86_64 ? "Advanced Micro Devices X86-64" : "Other");
    printf("  Version:                           0x%x\n", ehdr->e_version);
    printf("  Entry point address:               0x%lx\n", (unsigned long)ehdr->e_entry);
    printf("  Start of program headers:          %ld (bytes into file)\n", (long)ehdr->e_phoff);
    printf("  Start of section headers:          %ld (bytes into file)\n", (long)ehdr->e_shoff);
    printf("  Flags:                             0x%x\n", ehdr->e_flags);
    printf("  Size of this header:               %d (bytes)\n", ehdr->e_ehsize);
    printf("  Size of program headers:           %d (bytes)\n", ehdr->e_phentsize);
    printf("  Number of program headers:         %d\n", ehdr->e_phnum);
    printf("  Size of section headers:           %d (bytes)\n", ehdr->e_shentsize);
    printf("  Number of section headers:         %d\n", ehdr->e_shnum);
    printf("  Section header string table index: %d\n", ehdr->e_shstrndx);
}

void show_section_headers(int fd, Elf64_Ehdr ehdr, char *shstrtab) {
    printf("\nSection Headers:\n");
    printf("[Nr] %-17s %-15s %-8s %6s %6s %2s %3s %2s %3s %2s\n",
           "Name", "Type", "Addr", "Off", "Size", "ES", "Flg", "Lk", "Inf", "Al");

    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        read(fd, &shdr, sizeof(shdr));

        const char *name = shstrtab + shdr.sh_name;
        const char *type = get_section_type(shdr.sh_type);

        printf("[%2d] %-17s %-15s %08lx %06lx %06lx %02lx %3s %2d %3d %2ld\n",
               i, name, type, shdr.sh_addr, shdr.sh_offset, 
               shdr.sh_size, shdr.sh_entsize, "", shdr.sh_link, 
               shdr.sh_info, shdr.sh_addralign);
    }
}

void show_symbols(int fd, Elf64_Ehdr ehdr, char *shstrtab) {
    Elf64_Shdr symtab_hdr, strtab_hdr;

    for (int i = 0; i < ehdr.e_shnum; i++) {
        lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        read(fd, &symtab_hdr, sizeof(symtab_hdr));
        
        if (symtab_hdr.sh_type == SHT_SYMTAB) {
            lseek(fd, ehdr.e_shoff + symtab_hdr.sh_link * ehdr.e_shentsize, SEEK_SET);
            read(fd, &strtab_hdr, sizeof(strtab_hdr));
            
            char *strtab = malloc(strtab_hdr.sh_size);
            lseek(fd, strtab_hdr.sh_offset, SEEK_SET);
            read(fd, strtab, strtab_hdr.sh_size);

            printf("\nSYMBOL TABLE:\n");
            printf("%-16s %-8s %-8s %-8s %-8s %s\n", 
                   "ADDR", "SIZE", "TYPE", "BIND", "VIS", "NAME");

            for (unsigned j = 0; j < symtab_hdr.sh_size / sizeof(Elf64_Sym); j++) {
                Elf64_Sym sym;
                lseek(fd, symtab_hdr.sh_offset + j * sizeof(Elf64_Sym), SEEK_SET);
                read(fd, &sym, sizeof(sym));

                const char *name = strtab + sym.st_name;
                const char *type = (ELF64_ST_TYPE(sym.st_info) == STT_FUNC) ? "FUNC" : "OBJECT";
                const char *bind = (ELF64_ST_BIND(sym.st_info) == STB_GLOBAL) ? "GLOBAL" : "LOCAL";

                printf("%016lx %-8lx %-8s %-8s %-8s %s\n", 
                       sym.st_value, sym.st_size, type, bind, "DEFAULT", name);
            }
            free(strtab);
            break;
        }
    }
}

void show_relocations(int fd, Elf64_Ehdr ehdr, char *shstrtab, int dynamic) {
    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        read(fd, &shdr, sizeof(shdr));

        if ((!dynamic && shdr.sh_type == SHT_RELA) || 
            (dynamic && shdr.sh_type == SHT_DYNAMIC)) {
            
            const char *name = shstrtab + shdr.sh_name;
            printf("\nRELOCATION RECORDS FOR [%s]:\n", name);
            printf("%-16s %-16s %-16s %s\n", 
                   "OFFSET", "TYPE", "VALUE", "NAME");

            Elf64_Shdr symtab_hdr, strtab_hdr;
            lseek(fd, ehdr.e_shoff + shdr.sh_link * ehdr.e_shentsize, SEEK_SET);
            read(fd, &symtab_hdr, sizeof(symtab_hdr));
            lseek(fd, ehdr.e_shoff + symtab_hdr.sh_link * ehdr.e_shentsize, SEEK_SET);
            read(fd, &strtab_hdr, sizeof(strtab_hdr));
            
            char *strtab = malloc(strtab_hdr.sh_size);
            lseek(fd, strtab_hdr.sh_offset, SEEK_SET);
            read(fd, strtab, strtab_hdr.sh_size);

            for (unsigned j = 0; j < shdr.sh_size / sizeof(Elf64_Rela); j++) {
                Elf64_Rela rela;
                lseek(fd, shdr.sh_offset + j * sizeof(Elf64_Rela), SEEK_SET);
                read(fd, &rela, sizeof(rela));

                Elf64_Sym sym;
                lseek(fd, symtab_hdr.sh_offset + ELF64_R_SYM(rela.r_info) * sizeof(Elf64_Sym), SEEK_SET);
                read(fd, &sym, sizeof(sym));

                const char *sym_name = strtab + sym.st_name;
                const char *type = get_reloc_type(ELF64_R_TYPE(rela.r_info));

                printf("%016lx %-16s %016lx %s\n", 
                       rela.r_offset, type, rela.r_addend, sym_name);
            }
            free(strtab);
        }
    }
}

void show_hex_dump(int fd, Elf64_Ehdr ehdr, char *shstrtab) {
    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        read(fd, &shdr, sizeof(shdr));

        if (shdr.sh_type != SHT_NOBITS && shdr.sh_size > 0) {
            const char *name = shstrtab + shdr.sh_name;
            printf("\nHex dump of section '%s':\n", name);

            unsigned char *data = malloc(shdr.sh_size);
            lseek(fd, shdr.sh_offset, SEEK_SET);
            read(fd, data, shdr.sh_size);

            for (unsigned j = 0; j < shdr.sh_size; j += 16) {
                printf("  %04x ", j);
                for (int k = 0; k < 16; k++) {
                    if (j + k < shdr.sh_size) {
                        printf(" %02x", data[j + k]);
                    } else {
                        printf("   ");
                    }
                }
                printf("  ");
                for (int k = 0; k < 16 && j + k < shdr.sh_size; k++) {
                    printf("%c", isprint(data[j + k]) ? data[j + k] : '.');
                }
                printf("\n");
            }
            free(data);
        }
    }
}

void disassemble_section(int fd, Elf64_Shdr *shdr) {
    csh handle;
    cs_insn *insn;
    size_t count;
    uint8_t *code = malloc(shdr->sh_size);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perror("cs_open");
        return;
    }

    lseek(fd, shdr->sh_offset, SEEK_SET);
    read(fd, code, shdr->sh_size);

    printf("\nDisassembly of section .text:\n");
    count = cs_disasm(handle, code, shdr->sh_size, shdr->sh_addr, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            printf("  %lx:\t%-10s\t%s\n", insn[j].address, 
                   insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    } else {
        printf("Failed to disassemble\n");
    }

    cs_close(&handle);
    free(code);
}

int main(int argc, char **argv) {
    options_t opts;
    parse_args(argc, argv, &opts);

    int fd = open(opts.filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) < sizeof(ehdr)) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        exit(EXIT_FAILURE);
    }

    Elf64_Shdr shstrtab_hdr;
    lseek(fd, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, SEEK_SET);
    read(fd, &shstrtab_hdr, sizeof(shstrtab_hdr));
    
    char *shstrtab = malloc(shstrtab_hdr.sh_size);
    lseek(fd, shstrtab_hdr.sh_offset, SEEK_SET);
    read(fd, shstrtab, shstrtab_hdr.sh_size);

    if (opts.show_header) show_elf_header(&ehdr);
    if (opts.show_sections) show_section_headers(fd, ehdr, shstrtab);
    if (opts.show_symbols) show_symbols(fd, ehdr, shstrtab);
    if (opts.show_relocs) show_relocations(fd, ehdr, shstrtab, 0);
    if (opts.show_dyn_relocs) show_relocations(fd, ehdr, shstrtab, 1);
    if (opts.show_hex) show_hex_dump(fd, ehdr, shstrtab);
    if (opts.disassemble) {
        for (int i = 0; i < ehdr.e_shnum; i++) {
            Elf64_Shdr shdr;
            lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
            read(fd, &shdr, sizeof(shdr));
            
            const char *name = shstrtab + shdr.sh_name;
            if (strcmp(name, ".text") == 0) {
                disassemble_section(fd, &shdr);
                break;
            }
        }
    }

    free(shstrtab);
    close(fd);
    return 0;
}