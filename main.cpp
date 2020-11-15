#include <iostream>
#include <fstream>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <fmt/color.h>


namespace elf
{
    using u8  = uint8_t;
    using u16 = uint16_t;
    using u32 = uint32_t;
    using u64 = uint64_t;

    namespace ehdr
    {
        // ELF header identification bytes entries offsets.
        static constexpr u8 ELF_IDENT_SIZE         = 16;
        static constexpr u8 EHDR_OFFSET_CLASS      = 4;
        static constexpr u8 EHDR_OFFSET_DATA       = 5;   // affects interpretation of multi-byte field starting with offset 0x10
        static constexpr u8 EHDR_OFFSET_VERSION    = 6;
        static constexpr u8 EHDR_OFFSET_OS_ABI     = 7;
        static constexpr u8 EHDR_OFFSET_ABIVERSION = 8;
        // static constexpr u8 EHDR_OFFSET_PADDING    = 9;

        enum file_type : u16
        {
            ET_NONE    = 0x0,
            ET_REL     = 0x1,
            ET_EXEC    = 0x2,
            ET_DYN     = 0x3,
            ET_CORE    = 0x4,
            ET_LOOS    = 0xFE00,
            ET_HIOS    = 0xFEFF,
            ET_LOPROC  = 0xFF00,
            ET_HIPROC  = 0xFFFF
        };

        enum file_fmt_type : u8
        {
            FMT32BIT = 0x1,
            FMT64BIT = 0x2,
        };

        enum endianness_type : u8
        {
            ELFDATA2LSB = 0x1,
            ELFDATA2MSB = 0x2
        };

        template<typename WordSize>
        struct hdr_info
        {
            u8  ident_bytes[ELF_IDENT_SIZE];
            file_type type;           // 1 = relocatable, 2 = executable, 3 = shared, 4 = core
            u16 target;               // target machine
            u32 version;              // ELF file version
            WordSize entry;           // program entry position
            WordSize phdr_offset;     // program header offset in bytes
            WordSize shdr_offset;     // section header offset in bytes
            u32 unused_flags;         // unused flags for x86 ELF
            u16 ehdr_size;            // size of this header
            u16 phdr_entry_size;      // size of a program header table entry
            u16 phdr_amount;          // number of entries in the program header table
            u16 shdr_entry_size;      // size of a section header table entry
            u16 shdr_amount;          // number of entries in the section header table
            u16 shdr_str_index;       // index of the shdr entry that contains the section names.
        };

        using hdr32_info = hdr_info<u32>;
        using hdr64_info = hdr_info<u64>;

        std::string os_abi_str_from_u8(u8 byte)
        {
            switch (byte)
            {
                case 0x00: return "System V";
                case 0x01: return "HP-UX";
                case 0x02: return "NetBSD";
                case 0x03: return "Linux";
                case 0x04: return "GNU Hurd";
                case 0x06: return "Solaris";
                case 0x07: return "AIX";
                case 0x08: return "IRIX";
                case 0x09: return "FreeBSD";
                case 0x0A: return "Tru64";
                case 0x0B: return "Novell Modesto";
                case 0x0C: return "OpenBSD";
                case 0x0D: return "OpenVMS";
                case 0x0E: return "NonStop Kernel";
                case 0x0F: return "AROS";
                case 0x10: return "Fenix OS";
                case 0x11: return "CloudABI";
                case 0x12: return "Stratus Technologies OpenVOS";
                default:   return "Unknown ABI";
            }
        }

       std::string elf_type_str_from_file_t(file_type type)
       {
           switch (type)
           {
               case ET_NONE:   return "No file type";
               case ET_REL:    return "Relocatable file";
               case ET_EXEC:   return "Executable file";
               case ET_DYN:    return "Shared object file";
               case ET_CORE:   return "Core file";

               case ET_LOOS:
               case ET_HIOS:   return "Operating-system-specific";

               case ET_LOPROC:
               case ET_HIPROC: return "Processor-specific";
               default:        return "Invalid type";
           }
       }

        std::string target_str_from_u16(u16 byte)
        {
            // TODO: update these, see on english wikipedia page ISA
            switch (byte)
            {
                case 2:   return "SPARC";
                case 3:   return "Intel 80386";
                case 4:   return "Motorola 68000";
                case 7:   return "Intel i860";
                case 8:   return "MIPS I";
                case 19:  return "Intel i960";
                case 20:  return "Power PC";
                case 40:  return "ARM";
                case 50:  return "Intel IA64";
                case 62:  return "x64";
                case 243: return "RISC-V";
                default:  return "None";
            }
        }

        template<typename WordSize>
        void output_hdr_structure(const hdr_info<WordSize>& header)
        {
            fmt::print("┌ ELF Header ───────────────────────────────────────┐\n");
            fmt::print("│              Identification Fields\n");
            fmt::print("│ Raw:         {:02x}\n", fmt::join(header.ident_bytes, " "));

            if      (header.ident_bytes[EHDR_OFFSET_CLASS] == FMT32BIT)   fmt::print("│ Format:      32 bits (0x1)\n");
            else if (header.ident_bytes[EHDR_OFFSET_CLASS] == FMT64BIT)   fmt::print("│ Format:      64 bits (0x2)\n");

            if      (header.ident_bytes[EHDR_OFFSET_DATA] == ELFDATA2LSB) fmt::print("│ Endianness:  Little Endian (0x1)\n");
            else if (header.ident_bytes[EHDR_OFFSET_DATA] == ELFDATA2MSB) fmt::print("│ Endianness:  Big Endian (0x2)\n");
            else throw std::runtime_error(fmt::format("Endianness, expected 0x1 or 0x2 but got {:#x}", header.ident_bytes[EHDR_OFFSET_DATA]));

            fmt::print("│ ELF Version: {}\n", header.ident_bytes[EHDR_OFFSET_VERSION]);
            fmt::print("│ OS/ABI:      {}\n", os_abi_str_from_u8(header.ident_bytes[EHDR_OFFSET_OS_ABI]));
            fmt::print("│ ABI Version: {}\n", header.ident_bytes[EHDR_OFFSET_ABIVERSION]);

            fmt::print("│\n│                  Other Fields\n");
            fmt::print("│ File Type:                   {}\n",    elf_type_str_from_file_t(header.type));
            fmt::print("│ Machine:                     {}\n",    target_str_from_u16(header.target));
            fmt::print("│ ELF File Version:            {:#010x}\n", header.version);
            fmt::print("│ Entry Point Address:         {:#018x}\n", header.entry);
            fmt::print("│ Program Header Table Offset: {:#018x}\n", header.phdr_offset);
            fmt::print("│ Section Header Table Offset: {:#018x}\n", header.shdr_offset);
            fmt::print("│ Flags:                       {:#010x}\n", header.unused_flags);
            fmt::print("│ ELF Header Size:             {}\n",    header.ehdr_size);
            fmt::print("│ Program Header Entry Size:   {}\n",    header.phdr_entry_size);
            fmt::print("│ Program Header Amount:       {}\n",    header.phdr_amount);
            fmt::print("│ Section Header Entry Size:   {}\n",    header.shdr_entry_size);
            fmt::print("│ Section Header Amount:       {}\n",    header.shdr_amount);
            fmt::print("│ Section Header Name Index:   {}\n",    header.shdr_str_index);
            fmt::print("└───────────────────────────────────────────────────┘\n");
        }

        file_fmt_type read_fmt_type(std::ifstream& elf_stream)
        {
            elf_stream.seekg(EHDR_OFFSET_CLASS);
            const auto format = static_cast<file_fmt_type>(elf_stream.get());
            elf_stream.seekg(0);

            return format;
        }

        template<typename HdrType>
        HdrType read(std::ifstream& elf_stream)
        {
            HdrType header {};
            elf_stream.read(reinterpret_cast<char *>(&header), sizeof(HdrType));

            if (header.ident_bytes[0] != 0x7f ||
                header.ident_bytes[1] != 'E'  ||
                header.ident_bytes[2] != 'L'  ||
                header.ident_bytes[3] != 'F')
            {
                throw std::runtime_error("Mismatch in ELF file signature.");
            }

            return header;
        }
    }

    namespace phdr
    {
        enum phdr_type : u32
        {
            PT_NULL         = 0x00,
            PT_LOAD         = 0x01,
            PT_DYNAMIC      = 0x02,
            PT_INTERP       = 0x03,
            PT_NOTE         = 0x04,
            PT_SHLIB        = 0x05,
            PT_PHDR         = 0x06,
            PT_LTS          = 0x07,
            PT_LOOS         = 0x60000000,
            PT_HIOS         = 0x6FFFFFFF,
            PT_LOPROC       = 0x70000000,
            PT_HIPROC       = 0x7FFFFFFF,
            PT_GNU_EH_FRAME = 0x6474E550,
            PT_GNU_STACK    = 0x6474E551,
            PT_GNU_RELRO    = 0x6474E552,
            PT_GNU_PROPERTY = 0x6474e553
        };

        // The main thing that differs between 32 and 64 bits program headers, is the position of the flags.
        struct phdr32_info
        {
            phdr_type segtype;
            u32 offset;
            u32 vaddr;
            u32 paddr;
            u32 file_size;
            u32 mem_size;
            u32 flags;
            u32 align;
        };

        struct phdr64_info
        {
            phdr_type segtype;  // segment type
            u32 flags;          // read / write / execute
            u64 offset;         // the offset in the file where the data for this segment can be found
            u64 vaddr;          // virtual address of the segment in memory
            u64 paddr;          // reserved for segment's physical address
            u64 file_size;      // size in bytes of the segment in the file image
            u64 mem_size;       // size in bytes of the segment in memory
            u64 align;          // 0 and 1 specify no alignment, otherwise should be a positive, integral power of 2, with vaddr = offset % align
        };

        std::string segtype_to_str(phdr_type segtype)
        {
            switch (segtype)
            {
                case PT_NULL:         return "NULL";
                case PT_LOAD:         return "LOAD";
                case PT_DYNAMIC:      return "DYNAMIC";
                case PT_INTERP:       return "INTERP";
                case PT_NOTE:         return "NOTE";
                case PT_SHLIB:        return "SHLIB";
                case PT_PHDR:         return "PHDR";
                case PT_LTS:          return "LTS";
                case PT_LOOS:         return "LOOS";
                case PT_HIOS:         return "HIOS";
                case PT_LOPROC:       return "LOPROC";
                case PT_HIPROC:       return "HIPROC";
                case PT_GNU_EH_FRAME: return "GNU_EH_FRAM";
                case PT_GNU_STACK:    return "GNU_STACK";
                case PT_GNU_RELRO:    return "GNU_RELRO";
                case PT_GNU_PROPERTY: return "GNU_PROPERTY";
                default:              return "UNKNOWN SEGMENT TYPE";
            }
        }

        std::string flags_to_str(u32 flags)
        {
            std::string perm_str;

            if (flags & (1u << 2u)) perm_str += 'R';
            if (flags & (1u << 1u)) perm_str += 'W';
            if (flags & 1u)         perm_str += 'E';

            return perm_str;
        }

        template<typename PhdrT>
        void output_phdr_structure(const PhdrT& phdr, u16 phdr_index)
        {
            // We are using this function with 64 bits program header but also 32 bits
            // The problem is that we are using {:#018x} for formatting, meaning that it will ouput
            // values as 64 bits integer when they are in reality 32 bits
            fmt::print("┌────────────────── Program Header n°{} ─────────────┐\n", phdr_index);
            fmt::print("│ Segment Type: {} {:#010x}\n", segtype_to_str(phdr.segtype), phdr.segtype);
            fmt::print("│ Flags:        {}\n",          flags_to_str(phdr.flags));
            fmt::print("│ Offset:       {:#018x}\n",    phdr.offset);
            fmt::print("│ Virt. Addr.:  {:#018x}\n",    phdr.vaddr);
            fmt::print("│ Phys. Addr.:  {:#018x}\n",    phdr.paddr);
            fmt::print("│ File Size:    {:#018x}\n",    phdr.file_size);
            fmt::print("│ Mem. Size:    {:#018x}\n",    phdr.mem_size);
            fmt::print("│ Align:        {:#018x}\n",    phdr.align);
            fmt::print("└───────────────────────────────────────────────────┘\n");
        }

        void read_phdrs64(std::ifstream& elf_stream, ehdr::hdr64_info& header_info)
        {
            phdr64_info curr_phdr {};

            fmt::print("\n┌{0:─^51}\n", "  Program Headers Table  ");

            for (u16 phdr_index {0u}; phdr_index < header_info.phdr_amount; ++phdr_index)
            {
                size_t current_phdr_offset = header_info.phdr_offset + (header_info.phdr_entry_size * phdr_index);

                elf_stream.seekg(current_phdr_offset);
                elf_stream.read(reinterpret_cast<char *>(&curr_phdr), sizeof(phdr64_info));

                output_phdr_structure(curr_phdr, phdr_index + 1);
            }
        }
    }
}

void usage(const std::string& program_name)
{
    fmt::print("Usage: {} <file>\n", program_name);
}

void usage(const std::string& program_name, const std::string& error)
{
    fmt::print("[ERROR]: {}\n", error);
    usage(program_name);
}

int main(int argc, char** argv)
{
    if (argc == 1)
    {
        usage(argv[0], "File not specified");
        return EXIT_FAILURE;
    }

    std::ifstream elf_stream(argv[1], std::ios::in | std::ios::binary);

    if (!elf_stream)
    {
        fmt::print(stderr, "[ERROR]: Couldn't open file \"{}\"\n", argv[1]);
        return EXIT_FAILURE;
    }

    const elf::ehdr::file_fmt_type format = elf::ehdr::read_fmt_type(elf_stream);

    if (format == elf::ehdr::FMT32BIT)
    {

    } else if (format == elf::ehdr::FMT64BIT)
    {
        try
        {
            auto elf_header = elf::ehdr::read<elf::ehdr::hdr64_info>(elf_stream);

            elf::ehdr::output_hdr_structure(elf_header);
            elf::phdr::read_phdrs64(elf_stream, elf_header);

        } catch (const std::runtime_error& error)
        {
            fmt::print("[ERROR]: {}", error.what());
            return EXIT_FAILURE;
        }
    } else
    {
        fmt::print("[ERROR]: Couldn't read ELF format, expected 32 or 64 bits file format but got {}\n", format);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

