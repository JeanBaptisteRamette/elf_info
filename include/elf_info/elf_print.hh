#ifndef ELF_INFO_ELF_PRINT_HH
#define ELF_INFO_ELF_PRINT_HH

#include <vector>
#include <elf_info/elf_structs.hh>
#include <elf_info/elf.hh>
#include <fmt/core.h>
#include <fmt/ranges.h>


namespace print
{
    namespace
    {
        const char*
        file_type_to_str(ehdr::file_type type)
        {
            switch (type)
            {
                case ehdr::ET_NONE:   return "No file type";
                case ehdr::ET_REL:    return "Relocatable file";
                case ehdr::ET_EXEC:   return "Executable file";
                case ehdr::ET_DYN:    return "Shared object file";
                case ehdr::ET_CORE:   return "Core file";

                case ehdr::ET_LOOS:
                case ehdr::ET_HIOS:   return "Operating-system-specific";

                case ehdr::ET_LOPROC:
                case ehdr::ET_HIPROC: return "Processor-specific";
                default:              return "Invalid file type";
            }
        }

        const char*
        target_to_str(u16 tar_byte)
        {
            switch (tar_byte)
            {
                case 0x01:  return "AT&T WE 32100";
                case 0x02:  return "SPARC";
                case 0x03:  return "Intel 80386";
                case 0x04:  return "Motorola 68000";
                case 0x05:  return "Motorola 88000";
                case 0x06:  return "Intel MCU";
                case 0x07:  return "Intel 80860";
                case 0x08:  return "MIPS I";
                case 0x09:  return "IBM System/370";
                case 0x0A:  return "MIPS RS3000 Little Endian";

                case 0x0B:
                case 0x0C:
                case 0x0D:  return "Reserved for future use";

                case 0x0E:  return "Hewlett-Packard PA-RISC";
                case 0x0F:  return "Reserved for future use";
                case 0x13:  return "Intel 80960";
                case 0x14:  return "PowerPC";
                case 0x15:  return "PowerPC (64-bit)";
                case 0x16:  return "S390";
                case 0x28:  return "ARM";
                case 0x2A:  return "SuperH";
                case 0x32:  return "IA-64";
                case 0x3E:  return "amd64";
                case 0x8C:  return "TMS320C60000 Family";
                case 0xB7:  return "ARM 64-bits";
                case 0xF3:  return "RISC-V";
                case 0x101: return "WDC 65C816";
                default:    return "No specific instruction set";
            }
        }

        std::string ptype_tostr(phdr::phdr_type type)
        {
            using namespace phdr;
            switch (type)
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
                case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
                case PT_GNU_STACK:    return "GNU_STACK";
                case PT_GNU_RELRO:    return "GNU_RELRO";
                case PT_GNU_PROPERTY: return "GNU_PROPERTY";
                default:              return "Unknown type";
            }
        }

        std::string
        flags_to_str(u32 flags)
        {
            if (!(flags & 7u)) return "No Flags";

            const u32 pf_msk_os   = 0x0FF00000;
            const u32 pf_msk_proc = 0xF0000000;

            if (flags & pf_msk_os)   return "OS Spec";
            if (flags & pf_msk_proc) return "Proc Spec";

            std::string perm_str;
            if (flags & (1u << 2u)) perm_str += 'R';
            if (flags & (1u << 1u)) perm_str += 'W';
            if (flags & 1u)         perm_str += 'E';

            return perm_str;
        }
    }

    template<typename T>
    void
    output_ehdr_structure(const ehdr::ehdr_data<T> &eheader)
    {
        static_assert(std::is_same_v<T, u32> ||
                      std::is_same_v<T, u64>, "Incompatible data type for ELF header");

        // Make one big string then format it
        fmt::print("┌ ELF Header ───────────────────────────────────────┐\n");
        fmt::print("│             Identification Fields\n");
        fmt::print("│ Raw:         {:02x}\n", fmt::join(eheader.ident_bytes, " "));

        const auto class_fmt = eheader.ident_bytes[ehdr::OFFSET_CLASS];
        fmt::print("│ Format: {} bits\n", class_fmt * 32);

        const auto byte_ord = eheader.ident_bytes[ehdr::OFFSET_DATA];

        if (byte_ord == ehdr::ELFDATA2LSB)
            fmt::print("│ Endianness:  Little Endian (0x1)\n");
        else if (byte_ord == ehdr::ELFDATA2MSB)
            fmt::print("│ Endianness:  Big Endian (0x2)\n");
        else
            throw std::runtime_error("Unexpected byte order");

        fmt::print("│ ELF Version: {}\n", eheader.ident_bytes[ehdr::OFFSET_VERSION]);
        fmt::print("│ OS/ABI:      {}\n", eheader.ident_bytes[ehdr::OFFSET_OS_ABI]);
        fmt::print("│ ABI Version: {}\n", eheader.ident_bytes[ehdr::OFFSET_ABIVERSION]);
        fmt::print("│\n│                  Other Fields\n");
        fmt::print("│ File Type:                   {}\n",       file_type_to_str(eheader.type));
        fmt::print("│ Machine:                     {}\n",       target_to_str(eheader.target));
        fmt::print("│ ELF File Version:            {}\n",       eheader.version);
        fmt::print("│ Entry Point Address:         {:#018x}\n", eheader.entry);
        fmt::print("│ Program Header Table Offset: {:#018x}\n", eheader.phdr_offset);
        fmt::print("│ Section Header Table Offset: {:#018x}\n", eheader.shdr_offset);
        fmt::print("│ Flags:                       {:#010x}\n", eheader.flags);
        fmt::print("│ ELF Header Size:             {}\n",       eheader.ehdr_size);
        fmt::print("│ Program Header Entry Size:   {}\n",       eheader.phdr_entry_size);
        fmt::print("│ Program Header Amount:       {}\n",       eheader.phdr_amount);
        fmt::print("│ Section Header Entry Size:   {}\n",       eheader.shdr_entry_size);
        fmt::print("│ Section Header Amount:       {}\n",       eheader.shdr_amount);
        fmt::print("│ Section Header Name Index:   {}\n",       eheader.shdr_str_index);
        fmt::print("└───────────────────────────────────────────────────┘\n");
    }

    template<typename PhdrT>
    void
    output_phdr_structure(const PhdrT& phdr)
    {
        auto segstr = ptype_tostr(phdr.segtype);
        const auto pad_size = 15 - segstr.size();
        const auto phdr_line_info = fmt::format("{}{:<{}}{:#018x} {:#018x} {:#018x}\n"
                                                "{:<15}{:#018x} {:#018x} {:<9} {:#x}\n",
                                                segstr, " ", pad_size, phdr.offset, phdr.vaddr, phdr.paddr,
                                                " ", phdr.file_size, phdr.mem_size,
                                                flags_to_str(phdr.flags), phdr.align);
        fmt::print(phdr_line_info);
    }

    template<typename T>
    void
    output_shdr_structure(const shdr::shdr_data<T>& sheader [[maybe_unused]])
    {

    }

    template<typename T>
    void
    output_phdr_table(elf::elf<T>& elf_s)
    {
        static_assert(std::is_same_v<T, u32> ||
                      std::is_same_v<T, u64>, "Incompatible data type for ELF");

        const std::string cols = "Program Headers:\n"
                                "Type           Offset             Virt. Addr.        Phys. Addr.\n"
                                "               File Size          Memory Size        Flags     Align\n";

        fmt::print(cols);

        for (const auto& phdr : elf_s.get_phdr_table())
        {
            output_phdr_structure(phdr);

            if (phdr.segtype == phdr::phdr_type::PT_INTERP)
            {
                const std::string interpreter = elf::read_interp(elf_s.stream, phdr.offset, phdr.file_size);
                fmt::print("↳ [Requesting program interpreter {}]\n", interpreter);
            }
        }
    }

    template<typename T>
    void
    output_shdr_table(const std::vector<shdr::shdr_data<T>>& shdr_table)
    {
        static_assert(std::is_same_v<T, u32> ||
                      std::is_same_v<T, u64>, "Incompatible data type for section header");

        for (const auto& shdr : shdr_table)
            output_shdr_structure(shdr);
    }
}

#endif // ELF_INFO_ELF_PRINT_HH