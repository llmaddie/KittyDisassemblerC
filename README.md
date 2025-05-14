# 🛠️ KittyDisassembler

**KittyDisassembler** is a lightweight ELF file analyzer and disassembler written in C. It replicates some of the essential features of GNU `objdump`, such as viewing ELF headers, section headers, and disassembling binary code.

This tool is designed to help you understand the internal structure of ELF binaries and how disassembly works at a low level using only C and Capstone.

---

## 📦 Requirements

To compile and run `KittyDisassembler`, you need:

- A C compiler like `gcc`
- Capstone disassembly engine

### ✅ Install Capstone

#### On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install libcapstone-dev
```

#### On Arch

```bash
sudo pacman -S capstone
```

#### On MacOs
```bash
brew install capstone
```


### 🔧 Compilation

```bash
gcc KittyDisassembler.c -o KittyDisassembler -lcapstone
```

### 🚀 Usage

```bash
./medobjdump [option] <ELF file>
```

## Options

Option	Description

-h	Display ELF file headers (class, endian, OS/ABI, etc.)

-s	Display section headers (name, type, address, offset, size, etc.)

-d	Disassemble the .text section using Capstone

-all	Display everything: headers, sections, and disassembly

    ⚠️ The target file must be a valid 64-bit ELF binary.

For Any questions or idea contact me at @human01x on telegram
