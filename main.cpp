#include <iostream>
#include <fstream>


namespace elf
{
    using u8  = uint8_t;
    using u16 = uint16_t;
    using u32 = uint32_t;
    using u64 = uint64_t;


    namespace hdr
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
            std::cout << "ELF header ---------------------------------------\n";
            std::cout << "|              Identification Fields\n";
            std::cout << "| Raw:        " << std::hex;

            for (const u8 byte : header.ident_bytes) std::cout << +byte << ' ';

            std::cout << '\n';

            if      (header.ident_bytes[EHDR_OFFSET_CLASS] == FMT32BIT) std::cout << "| Format:      32 bits (0x1)";
            else if (header.ident_bytes[EHDR_OFFSET_CLASS] == FMT64BIT) std::cout << "| Format:      64 bits (0x2)";
            else std::cout << "| Format: Invalid value 0x" << +header.ident_bytes[EHDR_OFFSET_CLASS];

            std::cout << "|\n";

            if      (header.ident_bytes[EHDR_OFFSET_DATA] == ELFDATA2LSB) std::cout << "| Endianness:  Little Endian (0x1)\n";
            else if (header.ident_bytes[EHDR_OFFSET_DATA] == ELFDATA2MSB) std::cout << "| Endianness:  Big Endian (0x2)\n";
            else std::cout << "Endianness: Invalid value 0x" << +header.ident_bytes[EHDR_OFFSET_DATA] << '\n';

            std::cout << "| ELF Version: 0x" << +header.ident_bytes[EHDR_OFFSET_VERSION]                   << '\n';
            std::cout << "| OS/ABI:      "   << os_abi_str_from_u8(header.ident_bytes[EHDR_OFFSET_OS_ABI]) << '\n';
            std::cout << "| ABI Version: 0x" << +header.ident_bytes[EHDR_OFFSET_ABIVERSION]                << '\n';

            std::cout << "|\n|                  Other Fields\n";
            std::cout << "| File Type:                   "   << elf_type_str_from_file_t(header.type) << '\n';
            std::cout << "| Machine:                     "   << target_str_from_u16(header.target)    << '\n';
            std::cout << "| ELF File Version:            0x" << header.version                        << '\n';
            std::cout << "| Entry Point Address:         0x" << header.entry                          << '\n';
            std::cout << "| Program Header Table Offset: 0x" << header.phdr_offset                    << '\n';
            std::cout << "| Section Header Table Offset: 0x" << header.shdr_offset                    << '\n';
            std::cout << "| Flags:                       0x" << header.unused_flags                   << '\n';
            std::cout << "| ELF Header Size:             "   << std::dec << header.ehdr_size          << '\n';
            std::cout << "| Program Header Entry Size:   "   << header.phdr_entry_size                << '\n';
            std::cout << "| Program Header Amount:       "   << header.phdr_amount                    << '\n';
            std::cout << "| Section Header Entry Size:   "   << header.shdr_entry_size                << '\n';
            std::cout << "| Section Header Amount:       "   << header.shdr_amount                    << '\n';
            std::cout << "| Section Header Name Index:   "   << header.shdr_str_index                 << '\n';
            std::cout << "-------------------------------------------------\n";
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
        void output_phdr64_structure(const PhdrT& phdr, u16 phdr_index)
        {
            std::cout << std::dec;
            std::cout << "| ---- Program Header n° " << phdr_index << '\n' << std::hex;
            std::cout << "| Segment Type: "   << segtype_to_str(phdr.segtype) << " 0x" << phdr.segtype << '\n';
            std::cout << "| Flags:        "   << flags_to_str(phdr.flags)     << '\n';
            std::cout << "| Offset:       0x" << phdr.offset            << '\n';
            std::cout << "| Virt. Addr.:  0x" << phdr.vaddr             << '\n';
            std::cout << "| Phys. Addr.:  0x" << phdr.paddr             << '\n';
            std::cout << "| File Size:    0x" << phdr.file_size         << '\n';
            std::cout << "| Mem. Size:    0x" << phdr.mem_size          << '\n';
            std::cout << "| Align:        0x" << phdr.align             << "\n";
            std::cout << "--------------------------------------------------\n";
        }

        void read_phdrs64(std::ifstream& elf_stream, hdr::hdr64_info& header_info)
        {
            phdr64_info curr_phdr {};

            std::cout << "Program headers ----------------------------------\n";

            for (u16 phdr_index {0u}; phdr_index < header_info.phdr_amount; ++phdr_index)
            {
                size_t current_phdr_offset = header_info.phdr_offset + (header_info.phdr_entry_size * phdr_index);

                elf_stream.seekg(current_phdr_offset);
                elf_stream.read(reinterpret_cast<char *>(&curr_phdr), sizeof(phdr64_info));

                output_phdr64_structure(curr_phdr, phdr_index + 1);
            }
        }
    }
}

void usage(const std::string& program_name)
{
    std::cout << "Usage: " << program_name << " <file>\n";
}

void usage(const std::string& program_name, const std::string& error)
{
    std::cerr << "[ERROR]: " << error << '\n';
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
        std::cerr << "Couldn't open file\n";
        return EXIT_FAILURE;
    }

    const elf::hdr::file_fmt_type format = elf::hdr::read_fmt_type(elf_stream);

    if (format == elf::hdr::FMT32BIT)
    {
        auto elf_header = elf::hdr::read<elf::hdr::hdr32_info>(elf_stream);

    } else if (format == elf::hdr::FMT64BIT)
    {
        try
        {
            auto elf_header = elf::hdr::read<elf::hdr::hdr64_info>(elf_stream);
            elf::phdr::read_phdrs64(elf_stream, elf_header);
        } catch (const std::runtime_error& error)
        {
            std::cerr << "[ERROR]: " << error.what() << '\n';
            return EXIT_FAILURE;
        }
    } else
    {
        std::cerr << "[ERROR]: Couldn't read ELF format, expected 32 or 64 bits file format\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

