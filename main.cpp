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
        static constexpr u8 EHDR_OFFSET_PADDING    = 9;

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
            format_32bit = 0x1,
            format_64bit = 0x2,
        };

        enum endianness_type : u8
        {
            endianness_little = 0x1,
            endianness_big    = 0x2
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

            // Perhaps option to show only signature byte
            for (const u8 byte : header.ident_bytes) std::cout << +byte << ' ';

            std::cout << '\n';

            if (header.ident_bytes[EHDR_OFFSET_CLASS] == format_32bit)      std::cout << "| Format:      32 bit (0x1)";
            else if (header.ident_bytes[EHDR_OFFSET_CLASS] == format_64bit) std::cout << "| Format:      64 bit (0x2)";
            else std::cout << "| Format: Invalid value 0x" << +header.ident_bytes[EHDR_OFFSET_CLASS];

            std::cout << "|\n";

            if (header.ident_bytes[EHDR_OFFSET_DATA] == endianness_little)   std::cout << "| Endianness:  Little Endian (0x1)\n";
            else if (header.ident_bytes[EHDR_OFFSET_DATA] == endianness_big) std::cout << "| Endianness:  Big Endian (0x2)\n";
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

        void read_hdr32(std::ifstream& elf_stream, hdr32_info&)
        {

        }

        void read_hdr64(std::ifstream& elf_stream, hdr64_info& header)
        {
            elf_stream.read(reinterpret_cast<char *>(&header), sizeof(hdr64_info));

            // now verify the bytes are valid.
            if (header.ident_bytes[0] != 0x7f ||
                header.ident_bytes[1] != 'E'  ||
                header.ident_bytes[2] != 'L'  ||
                header.ident_bytes[3] != 'F')
            {
                std::cerr << "[ERROR]: mismatch in ELF file signature\n";
                return;
            }

            output_hdr_structure(header);
        }
    }
}

void usage(const std::string& program, const std::string& error)
{
    std::cout << "[ERROR]: File must be specified\n";
    std::cout << "Usage: " << program << " file\n";
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

    if (format == elf::hdr::format_32bit)
    {
        elf::hdr::hdr32_info header;
        elf::hdr::read_hdr32(elf_stream, header);
    } else if (format == elf::hdr::format_64bit)
    {
        elf::hdr::hdr64_info header;
        elf::hdr::read_hdr64(elf_stream, header);
    } else
    {
        std::cerr << "[ERROR]: Couldn't read ELF format, expected 32 bit or 64 bit file format\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

