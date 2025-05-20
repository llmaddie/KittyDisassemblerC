#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <capstone/capstone.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <json-c/json.h>

#define MAX_STRING_LEN 1024

typedef struct {
    int show_sections;
    int show_symbols;
    int disassemble;
    int show_header;
    int show_relocs;
    int show_dyn_relocs;
    int show_hex;
    int show_segments;
    int detect_syscalls;
    int extract_strings;
    int generate_cfg;
    int json_output;
    char *filename;
    char *output_file;
} options_t;

void parse_args(int argc, char **argv, options_t *opts) {
    memset(opts, 0, sizeof(options_t));
    opts->filename = NULL;

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
                    case 'p': opts->show_segments = 1; break;
                    case 's': opts->detect_syscalls = 1; break;
                    case 'S': opts->extract_strings = 1; break;
                    case 'c': opts->generate_cfg = 1; break;
                    case 'j': opts->json_output = 1; break;
                }
            }
        } else if (strncmp(argv[i], "--output=", 9) == 0) {
            opts->output_file = argv[i] + 9;
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
        case SHT_DYNAMIC: return "DYNAMIC";
        case SHT_NOTE: return "NOTE";
        case SHT_SHLIB: return "SHLIB";
        case SHT_HASH: return "HASH";
        case SHT_GNU_verdef: return "VERDEF";
        case SHT_GNU_verneed: return "VERNEED";
        case SHT_GNU_versym: return "VERSYM";
        default: return "UNKNOWN";
    }
}

const char *get_segment_type(uint32_t type) {
    switch(type) {
        case PT_NULL: return "NULL";
        case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP: return "INTERP";
        case PT_NOTE: return "NOTE";
        case PT_SHLIB: return "SHLIB";
        case PT_PHDR: return "PHDR";
        case PT_TLS: return "TLS";
        case PT_GNU_EH_FRAME: return "EH_FRAME";
        case PT_GNU_STACK: return "STACK";
        case PT_GNU_RELRO: return "RELRO";
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
        case R_X86_64_IRELATIVE: return "R_X86_64_IRELATIVE";
        default: return "UNKNOWN";
    }
}

void print_flags(uint64_t flags) {
    if (flags & PF_X) putchar('X');
    if (flags & PF_W) putchar('W');
    if (flags & PF_R) putchar('R');
}

void show_elf_header(Elf64_Ehdr *ehdr, json_object *jobj) {
    if (!jobj) {
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
    } else {
        json_object_object_add(jobj, "class", json_object_new_string(ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64" : "ELF32"));
        json_object_object_add(jobj, "type", json_object_new_string(ehdr->e_type == ET_EXEC ? "EXEC" : ehdr->e_type == ET_DYN ? "DYN" : "OTHER"));
        json_object_object_add(jobj, "machine", json_object_new_string(ehdr->e_machine == EM_X86_64 ? "x86_64" : "OTHER"));
        json_object_object_add(jobj, "entry_point", json_object_new_int64(ehdr->e_entry));
    }
}

void show_segments(int fd, Elf64_Ehdr ehdr, json_object *jobj) {
    if (!jobj) {
        printf("\nProgram Headers:\n");
        printf("  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align\n");
    } else {
        json_object *jsegments = json_object_new_array();
        json_object_object_add(jobj, "segments", jsegments);
    }

    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        lseek(fd, ehdr.e_phoff + i * ehdr.e_phentsize, SEEK_SET);
        read(fd, &phdr, sizeof(phdr));

        if (!jobj) {
            printf("  %-14s 0x%06lx 0x%016lx 0x%016lx 0x%06lx 0x%06lx ",
                   get_segment_type(phdr.p_type), 
                   (unsigned long)phdr.p_offset,
                   (unsigned long)phdr.p_vaddr,
                   (unsigned long)phdr.p_paddr,
                   (unsigned long)phdr.p_filesz,
                   (unsigned long)phdr.p_memsz);
            print_flags(phdr.p_flags);
            printf(" 0x%lx\n", (unsigned long)phdr.p_align);
        } else {
            json_object *jsegment = json_object_new_object();
            json_object_object_add(jsegment, "type", json_object_new_string(get_segment_type(phdr.p_type)));
            json_object_object_add(jsegment, "offset", json_object_new_int64(phdr.p_offset));
            json_object_object_add(jsegment, "vaddr", json_object_new_int64(phdr.p_vaddr));
            json_object_object_add(jsegment, "filesz", json_object_new_int64(phdr.p_filesz));
            json_object_object_add(jsegment, "flags", json_object_new_int(phdr.p_flags));
            json_object_array_add(json_object_object_get(jobj, "segments"), jsegment);
        }
    }
}

void show_section_headers(int fd, Elf64_Ehdr ehdr, char *shstrtab, json_object *jobj) {
    if (!jobj) {
        printf("\nSection Headers:\n");
        printf("[Nr] %-17s %-15s %-8s %6s %6s %2s %3s %2s %3s %2s\n",
               "Name", "Type", "Addr", "Off", "Size", "ES", "Flg", "Lk", "Inf", "Al");
    } else {
        json_object *jsections = json_object_new_array();
        json_object_object_add(jobj, "sections", jsections);
    }

    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        read(fd, &shdr, sizeof(shdr));

        const char *name = shstrtab + shdr.sh_name;
        const char *type = get_section_type(shdr.sh_type);

        if (!jobj) {
            printf("[%2d] %-17s %-15s %08lx %06lx %06lx %02lx %3s %2d %3d %2ld\n",
                   i, name, type, shdr.sh_addr, shdr.sh_offset, 
                   shdr.sh_size, shdr.sh_entsize, "", shdr.sh_link, 
                   shdr.sh_info, shdr.sh_addralign);
        } else {
            json_object *jsection = json_object_new_object();
            json_object_object_add(jsection, "name", json_object_new_string(name));
            json_object_object_add(jsection, "type", json_object_new_string(type));
            json_object_object_add(jsection, "addr", json_object_new_int64(shdr.sh_addr));
            json_object_object_add(jsection, "offset", json_object_new_int64(shdr.sh_offset));
            json_object_object_add(jsection, "size", json_object_new_int64(shdr.sh_size));
            json_object_array_add(json_object_object_get(jobj, "sections"), jsection);
        }
    }
}

void show_symbols(int fd, Elf64_Ehdr ehdr, char *shstrtab, int dynamic, json_object *jobj) {
    Elf64_Shdr symtab_hdr, strtab_hdr;
    const char *symtab_type = dynamic ? "DYNSYM" : "SYMTAB";
    json_object *jsymbols = jobj ? json_object_new_array() : NULL;

    if (jobj) {
        json_object_object_add(jobj, dynamic ? "dyn_symbols" : "symbols", jsymbols);
    }

    for (int i = 0; i < ehdr.e_shnum; i++) {
        lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        read(fd, &symtab_hdr, sizeof(symtab_hdr));
        
        if ((!dynamic && symtab_hdr.sh_type == SHT_SYMTAB) || 
            (dynamic && symtab_hdr.sh_type == SHT_DYNSYM)) {
            
            lseek(fd, ehdr.e_shoff + symtab_hdr.sh_link * ehdr.e_shentsize, SEEK_SET);
            read(fd, &strtab_hdr, sizeof(strtab_hdr));
            
            char *strtab = malloc(strtab_hdr.sh_size);
            lseek(fd, strtab_hdr.sh_offset, SEEK_SET);
            read(fd, strtab, strtab_hdr.sh_size);

            if (!jobj) {
                printf("\n%s SYMBOL TABLE:\n", symtab_type);
                printf("%-16s %-8s %-8s %-8s %-8s %s\n", 
                       "ADDR", "SIZE", "TYPE", "BIND", "VIS", "NAME");
            }

            for (unsigned j = 0; j < symtab_hdr.sh_size / sizeof(Elf64_Sym); j++) {
                Elf64_Sym sym;
                lseek(fd, symtab_hdr.sh_offset + j * sizeof(Elf64_Sym), SEEK_SET);
                read(fd, &sym, sizeof(sym));

                const char *name = strtab + sym.st_name;
                const char *type = (ELF64_ST_TYPE(sym.st_info) == STT_FUNC) ? "FUNC" : 
                                  (ELF64_ST_TYPE(sym.st_info) == STT_OBJECT) ? "OBJECT" : "OTHER";
                const char *bind = (ELF64_ST_BIND(sym.st_info) == STB_GLOBAL) ? "GLOBAL" : 
                                  (ELF64_ST_BIND(sym.st_info) == STB_WEAK) ? "WEAK" : "LOCAL";

                if (!jobj) {
                    printf("%016lx %-8lx %-8s %-8s %-8s %s\n", 
                           sym.st_value, sym.st_size, type, bind, "DEFAULT", name);
                } else {
                    json_object *jsymbol = json_object_new_object();
                    json_object_object_add(jsymbol, "name", json_object_new_string(name));
                    json_object_object_add(jsymbol, "type", json_object_new_string(type));
                    json_object_object_add(jsymbol, "value", json_object_new_int64(sym.st_value));
                    json_object_object_add(jsymbol, "size", json_object_new_int64(sym.st_size));
                    json_object_array_add(jsymbols, jsymbol);
                }
            }
            free(strtab);
            break;
        }
    }
}

void show_relocations(int fd, Elf64_Ehdr ehdr, char *shstrtab, int dynamic, json_object *jobj) {
    const char *reloc_type = dynamic ? "DYNAMIC" : "REL";
    json_object *jrelocs = jobj ? json_object_new_array() : NULL;

    if (jobj) {
        json_object_object_add(jobj, dynamic ? "dyn_relocations" : "relocations", jrelocs);
    }

    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        read(fd, &shdr, sizeof(shdr));

        if ((!dynamic && shdr.sh_type == SHT_RELA) || 
            (dynamic && shdr.sh_type == SHT_DYNAMIC)) {
            
            const char *name = shstrtab + shdr.sh_name;
            if (!jobj) {
                printf("\n%s RELOCATION RECORDS FOR [%s]:\n", reloc_type, name);
                printf("%-16s %-16s %-16s %s\n", 
                       "OFFSET", "TYPE", "VALUE", "NAME");
            }

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

                if (!jobj) {
                    printf("%016lx %-16s %016lx %s\n", 
                           rela.r_offset, type, rela.r_addend, sym_name);
                } else {
                    json_object *jreloc = json_object_new_object();
                    json_object_object_add(jreloc, "offset", json_object_new_int64(rela.r_offset));
                    json_object_object_add(jreloc, "type", json_object_new_string(type));
                    json_object_object_add(jreloc, "name", json_object_new_string(sym_name));
                    json_object_array_add(jrelocs, jreloc);
                }
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

void extract_ascii_strings(unsigned char *data, size_t size) {
    printf("\nASCII Strings:\n");
    int in_string = 0;
    int start = 0;
    
    for (size_t i = 0; i < size; i++) {
        if (isprint(data[i]) && !in_string) {
            in_string = 1;
            start = i;
        } else if ((!isprint(data[i]) || i == size - 1)) {
            if (in_string && (i - start) >= 4) {
                printf("  %08zx: ", start);
                for (int j = start; j < (i == size - 1 ? i + 1 : i); j++) {
                    printf("%c", isprint(data[j]) ? data[j] : '.');
                }
                printf("\n");
            }
            in_string = 0;
        }
    }
}

void detect_syscalls(csh handle, cs_insn *insn, size_t count) {
    printf("\nDetected Syscalls:\n");
    for (size_t i = 0; i < count; i++) {
        if (strcmp(insn[i].mnemonic, "syscall") == 0) {
            // Look backwards for mov eax/rax, <syscall_num>
            for (int j = i - 1; j >= 0 && j > i - 10; j--) {
                if (strcmp(insn[j].mnemonic, "mov") == 0 && 
                    (strstr(insn[j].op_str, "eax") || strstr(insn[j].op_str, "rax"))) {
                    printf("  %lx: %s %s (syscall %s)\n", 
                           insn[i].address, insn[j].mnemonic, insn[j].op_str, insn[j].op_str);
                    break;
                }
            }
        }
    }
}

void generate_cfg(csh handle, cs_insn *insn, size_t count, const char *output_file) {
    FILE *dot = fopen(output_file ? output_file : "cfg.dot", "w");
    if (!dot) {
        perror("fopen");
        return;
    }

    fprintf(dot, "digraph CFG {\n");
    fprintf(dot, "  node [shape=box, fontname=\"Courier\"];\n");

    // Basic blocks detection (simplified)
    size_t prev_addr = insn[0].address;
    fprintf(dot, "  block_%lx [label=\"", prev_addr);
    
    for (size_t i = 0; i < count; i++) {
        // Detect block boundaries (jumps, calls, rets)
        if (strcmp(insn[i].mnemonic, "jmp") == 0 || 
            strcmp(insn[i].mnemonic, "ret") == 0 ||
            strcmp(insn[i].mnemonic, "call") == 0) {
            
            // Close current block
            fprintf(dot, "\"];\n");
            
            // Add edges for jumps/calls
            if (strcmp(insn[i].mnemonic, "jmp") == 0 || 
                strcmp(insn[i].mnemonic, "call") == 0) {
                uint64_t target;
                if (sscanf(insn[i].op_str, "0x%lx", &target) == 1) {
                    fprintf(dot, "  block_%lx -> block_%lx;\n", prev_addr, target);
                }
            }
            
            // Start new block if not at end
            if (i + 1 < count) {
                prev_addr = insn[i+1].address;
                fprintf(dot, "  block_%lx [label=\"", prev_addr);
            }
        } else {
            // Add instruction to current block
            fprintf(dot, "0x%lx: %s %s\\l", 
                   insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
    }
    
    fprintf(dot, "}\n");
    fclose(dot);
    printf("\nCFG generated in %s\n", output_file ? output_file : "cfg.dot");
}

void disassemble_section(int fd, Elf64_Shdr *shdr, options_t *opts) {
    csh handle;
    cs_insn *insn;
    size_t count;
    uint8_t *code = malloc(shdr->sh_size);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perror("cs_open");
        free(code);
        return;
    }

    lseek(fd, shdr->sh_offset, SEEK_SET);
    read(fd, code, shdr->sh_size);

    if (!opts->json_output) {
        printf("\nDisassembly of section .text:\n");
    }

    count = cs_disasm(handle, code, shdr->sh_size, shdr->sh_addr, 0, &insn);
    if (count > 0) {
        if (opts->json_output) {
            json_object *jinstructions = json_object_new_array();
            for (size_t j = 0; j < count; j++) {
                json_object *jinst = json_object_new_object();
                json_object_object_add(jinst, "address", json_object_new_int64(insn[j].address));
                json_object_object_add(jinst, "mnemonic", json_object_new_string(insn[j].mnemonic));
                json_object_object_add(jinst, "op_str", json_object_new_string(insn[j].op_str));
                json_object_array_add(jinstructions, jinst);
            }
            
            char json_str[256];
            snprintf(json_str, sizeof(json_str), "disasm_%lx.json", shdr->sh_addr);
            FILE *json_file = fopen(json_str, "w");
            if (json_file) {
                fprintf(json_file, "%s\n", json_object_to_json_string_ext(jinstructions, JSON_C_TO_STRING_PRETTY));
                fclose(json_file);
                printf("Disassembly exported to %s\n", json_str);
            }
            json_object_put(jinstructions);
        } else {
            for (size_t j = 0; j < count; j++) {
                printf("  %lx:\t%-10s\t%s\n", insn[j].address, 
                       insn[j].mnemonic, insn[j].op_str);
            }
        }

        if (opts->detect_syscalls) {
            detect_syscalls(handle, insn, count);
        }
        
        if (opts->generate_cfg) {
            generate_cfg(handle, insn, count, opts->output_file);
        }

        cs_free(insn, count);
    } else {
        printf("Failed to disassemble\n");
    }

    cs_close(&handle);
    free(code);
}

int analyze_file(const char *filename, options_t *opts) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) < sizeof(ehdr)) {
        perror("read");
        close(fd);
        return EXIT_FAILURE;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        close(fd);
        return EXIT_FAILURE;
    }

    Elf64_Shdr shstrtab_hdr;
    lseek(fd, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, SEEK_SET);
    read(fd, &shstrtab_hdr, sizeof(shstrtab_hdr));
    
    char *shstrtab = malloc(shstrtab_hdr.sh_size);
    lseek(fd, shstrtab_hdr.sh_offset, SEEK_SET);
    read(fd, shstrtab, shstrtab_hdr.sh_size);

    json_object *jobj = opts->json_output ? json_object_new_object() : NULL;

    if (opts->show_header) show_elf_header(&ehdr, jobj);
    if (opts->show_segments) show_segments(fd, ehdr, jobj);
    if (opts->show_sections) show_section_headers(fd, ehdr, shstrtab, jobj);
    if (opts->show_symbols) show_symbols(fd, ehdr, shstrtab, 0, jobj);
    if (opts->show_dyn_relocs) show_symbols(fd, ehdr, shstrtab, 1, jobj);
    if (opts->show_relocs) show_relocations(fd, ehdr, shstrtab, 0, jobj);
    if (opts->show_dyn_relocs) show_relocations(fd, ehdr, shstrtab, 1, jobj);
    if (opts->show_hex) show_hex_dump(fd, ehdr, shstrtab);

    if (opts->disassemble || opts->detect_syscalls || opts->generate_cfg) {
        for (int i = 0; i < ehdr.e_shnum; i++) {
            Elf64_Shdr shdr;
            lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
            read(fd, &shdr, sizeof(shdr));
            
            const char *name = shstrtab + shdr.sh_name;
            if ((shdr.sh_flags & SHF_EXECINSTR) && shdr.sh_size > 0) {
                disassemble_section(fd, &shdr, opts);
            }
        }
    }

    if (opts->extract_strings) {
        for (int i = 0; i < ehdr.e_shnum; i++) {
            Elf64_Shdr shdr;
            lseek(fd, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
            read(fd, &shdr, sizeof(shdr));

            if (shdr.sh_type != SHT_NOBITS && shdr.sh_size > 0) {
                unsigned char *data = malloc(shdr.sh_size);
                lseek(fd, shdr.sh_offset, SEEK_SET);
                read(fd, data, shdr.sh_size);
                extract_ascii_strings(data, shdr.sh_size);
                free(data);
            }
        }
    }

    if (jobj) {
        const char *json_str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY);
        if (opts->output_file) {
            FILE *json_file = fopen(opts->output_file, "w");
            if (json_file) {
                fprintf(json_file, "%s\n", json_str);
                fclose(json_file);
                printf("Analysis exported to %s\n", opts->output_file);
            } else {
                perror("fopen");
            }
        } else {
            printf("%s\n", json_str);
        }
        json_object_put(jobj);
    }

    free(shstrtab);
    close(fd);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    options_t opts;
    parse_args(argc, argv, &opts);

    if (!opts.filename) {
        fprintf(stderr, "Usage: %s [options] <elf_file>\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -h  Show section headers\n");
        fprintf(stderr, "  -t  Show symbol table\n");
        fprintf(stderr, "  -d  Disassemble executable sections\n");
        fprintf(stderr, "  -f  Show ELF header\n");
        fprintf(stderr, "  -r  Show relocations\n");
        fprintf(stderr, "  -R  Show dynamic relocations\n");
        fprintf(stderr, "  -x  Show hex dump of sections\n");
        fprintf(stderr, "  -p  Show program headers/segments\n");
        fprintf(stderr, "  -s  Detect syscalls in disassembly\n");
        fprintf(stderr, "  -S  Extract ASCII strings\n");
        fprintf(stderr, "  -c  Generate Control Flow Graph (CFG)\n");
        fprintf(stderr, "  -j  Output in JSON format\n");
        fprintf(stderr, "  --output=file  Save output to file\n");
        return EXIT_FAILURE;
    }

    return analyze_file(opts.filename, &opts);
}
