#ifndef ELF_INFO_ELF_PRINT_HH
#define ELF_INFO_ELF_PRINT_HH

#include <vector>
#include <elf_info/elf_types.hh>
#include <elf_info/elf.hh>
#include <elf_info/elf_utils.hh>
#include <fmt/core.h>
#include <fmt/printf.h>
#include <fmt/ranges.h>


namespace print
{
    constexpr std::string::size_type MAX_SECTION_NAME_LEN { 18 };
    constexpr std::string::size_type MAX_SECTION_TYPE_LEN { 17 };

    template<typename T>
    void
    output_ehdr_structure(const ehdr::ehdr_data<T> &eheader)
    {
        static_assert(std::is_same_v<T, u32> ||
                      std::is_same_v<T, u64>, "Incompatible data type for ELF header");

        const char* format { "┌ ELF Header ───────────────────────────────────────┐\n"
                                   "│             Identification Fields\n"
                                   "│ Raw:         {:02x}\n"
                                   "│ Format: {} bits\n"
                                   "│ Endianness: {}\n"
                                   "│ ELF Version: {}\n"
                                   "│ OS/ABI:      {}\n"
                                   "│ ABI Version: {}\n"
                                   "│\n│                  Other Fields\n"
                                   "│ File Type:                   {}\n"
                                   "│ Machine:                     {}\n"
                                   "│ ELF File Version:            {}\n"
                                   "│ Entry Point Address:         {:#018x}\n"
                                   "│ Program Header Table Offset: {:#018x}\n"
                                   "│ Section Header Table Offset: {:#018x}\n"
                                   "│ Flags:                       {:#010x}\n"
                                   "│ ELF Header Size:             {}\n"
                                   "│ Program Header Entry Size:   {}\n"
                                   "│ Program Header Amount:       {}\n"
                                   "│ Section Header Entry Size:   {}\n"
                                   "│ Section Header Amount:       {}\n"
                                   "│ Section Header Name Index:   {}\n"
                                   "└───────────────────────────────────────────────────┘\n" };

        const auto byte_ord { eheader.ident_bytes[ehdr::OFFSET_DATA] };
        const char* endianness;

        if (byte_ord == ehdr::ELFDATA2LSB)
            endianness = "Little Endian 2's complement";
        else if (byte_ord == ehdr::ELFDATA2MSB)
            endianness = "Big Endian 2's complement";
        else
            throw std::runtime_error("unexpected byte order");

        const auto formatted { fmt::format(format, fmt::join(eheader.ident_bytes, " "),
                                                   eheader.ident_bytes[ehdr::OFFSET_CLASS] * 32,
                                                   endianness,
                                                   eheader.ident_bytes[ehdr::OFFSET_VERSION],
                                                   eheader.ident_bytes[ehdr::OFFSET_OS_ABI],
                                                   eheader.ident_bytes[ehdr::OFFSET_ABIVERSION],
                                                   utils::file_type_to_str(eheader.type),
                                                   utils::target_to_str(eheader.target),
                                                   eheader.version,
                                                   eheader.entry,
                                                   eheader.phdr_offset,
                                                   eheader.shdr_offset,
                                                   eheader.flags,
                                                   eheader.ehdr_size,
                                                   eheader.phdr_entry_size,
                                                   eheader.phdr_amount,
                                                   eheader.shdr_entry_size,
                                                   eheader.shdr_amount,
                                                   eheader.shdr_str_index) };

        fmt::print(formatted);
    }

    template<typename PhdrT>
    void
    output_phdr_structure(const PhdrT& phdr)
    {
        const auto segstr { utils::ptype_tostr(phdr.segtype) };
        const auto pad_size { 15 - segstr.size() };
        const auto phdr_line_info { fmt::format("{}{:<{}}{:#018x} {:#018x} {:#018x}\n"
                                                "{:<15}{:#018x} {:#018x} {:<9} {:#x}\n",
                                                segstr, " ", pad_size, phdr.offset, phdr.vaddr, phdr.paddr,
                                                " ", phdr.file_size, phdr.mem_size,
                                                utils::phdr_flags_tostr(phdr.flags), phdr.align) };
        fmt::print(phdr_line_info);
    }

    template<typename T>
    void output_phdr_table(const elf::elf<T>& elf_s)
    {
        static_assert(std::is_same_v<T, u32> ||
                      std::is_same_v<T, u64>, "Incompatible data type for ELF");

        const char* fields { "Program Headers:\n"
                                   "Type           Offset             Virt. Addr.        Phys. Addr.\n"
                                   "               File Size          Memory Size        Flags     Align\n" };

        fmt::print(fields);

        for (const auto& phdr : elf_s.get_phdr_table())
        {
            output_phdr_structure(phdr);

            if (phdr.segtype == phdr::phdr_type::PT_INTERP)
            {
                const auto interpreter_name { elf_s.read_string(phdr.offset, phdr.file_size) };
                fmt::print("↳ [Requesting program interpreter {}]\n", interpreter_name);
            }
        }
    }

    template<typename T>
    void
    output_shdr_structure(std::string& name,
                          const shdr::shdr_data<T>& sheader,
                          u16 shdr_index, int num_max_width)
    {
        /* resize strings for output alignement */
        auto clamp = [](auto& str, auto size)
        {
            if (str.size() > size) str.resize(size);
            else str.resize(size, ' ');
        };

        auto type { utils::stype_tostr(sheader.sec_type) };

        clamp(name, MAX_SECTION_NAME_LEN);
        clamp(type, MAX_SECTION_TYPE_LEN);

        const auto shdr_line_info { fmt::format("[{:{}}]   {}  {}  {:#018x} {:#010x}\n"
                                                "       {:#018x}  {:#018x} {} {}       {}       {}\n",
                                                shdr_index, num_max_width, name, type, sheader.vaddr, sheader.offset,
                                                sheader.size, sheader.entry_size, utils::shdr_flags_tostr(sheader.flags), sheader.link, sheader.ex_info, sheader.addr_algn) };

        fmt::print(shdr_line_info);
    }

    template<typename T>
    void
    output_shdr_table(const elf::elf<T>& elf_s)
    {
        static_assert(std::is_same_v<T, u32> ||
                      std::is_same_v<T, u64>, "Incompatible data type for section header");

        const char* fields { "Section Headers:\n"
                                 "[Num.] Name                Type               Address            Offset\n"
                                 "       Size                Entry Size         Flags       Link    Info    Align\n" };

        fmt::print(fields);

        const auto& shdr_table { elf_s.get_shdr_table() };
        const int num_max_width { utils::digit_count(shdr_table.size()) };
        const auto table_size { shdr_table.size() };
        auto shdrstr_index { elf_s.get_file_header().shdr_str_index };

        if (shdrstr_index == shdr::SHN_XINDEX)
             shdrstr_index = shdr_table[0].link;

        if (shdrstr_index > table_size)
        {
            fmt::print(stderr, "Could not retrieve the section name string table.\n");
            return;
        }

        const auto& shdrstr { shdr_table[shdrstr_index] };

        for (u16 i = 0; i < table_size; ++i)
        {
            const auto& shdr { shdr_table[i] };

            std::string section_name;

            // Handle case where there is no section name string table
            if (shdrstr_index != shdr::SHN_UNDEF)
                section_name =  elf_s.read_section_name(shdr.name_offset, shdrstr);
            else
                section_name = {MAX_SECTION_NAME_LEN, ' '};

            output_shdr_structure(section_name, shdr, i, num_max_width);
        }

        const char* flags_mapping { "Flags:\n"
                                          "W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n"
                                          "L (link order), O (extra OS processing required), G (group), T (TLS),\n"
                                          "x (unknown), o (OS specific), E (exclude),\n"
                                          "l (large), p (processor specific)\n" };

        fmt::print(flags_mapping);
    }

    template<typename T>
    void
    hexdump_section(const elf::elf<T>& elf_s, std::string_view section_name)
    {
        const auto& section_header_table { elf_s.get_shdr_table() };

        const u16 shdrstr_index { elf_s.get_file_header().shdr_str_index };

        if (shdrstr_index == shdr::SHN_UNDEF)
        {
            fmt::print("Can not retrieve section '{}' because the file doesn't have a section header string table\n", section_name);
            return;
        }

        auto dump_section = [&](const shdr::shdr_data<T>& shdr) -> void
        {
            fmt::print("Dump of section '{}':\n\n", section_name);

            const std::vector<u8> content { elf_s.read_section_content(shdr) };

            if (!content.empty())
            {
                const char* data { reinterpret_cast<const char*>(content.data()) };
                T addr { shdr.vaddr };
                T num_bytes { shdr.size };

                // print one line by iteration
                while (num_bytes)
                {
                    T lbytes { (num_bytes > 16 ? 16 : num_bytes) };

                    fmt::print("  {:#010x}: ", addr);

                    for (auto j { 0u }; j < 16; ++j)
                    {
                        if (j < lbytes)
                            fmt::printf("%2.2x", data[j]);
                        else
                            fmt::print("  ");

                        if ((j & 3u) == 3)
                            fmt::print(" ");
                    }

                    for (auto j { 0u }; j < lbytes; ++j)
                    {
                        char byte { data[j] };
                        if (byte >= ' ' && byte < 0x7f) fmt::print("{}", byte);
                        else                            fmt::print(".");
                    }

                    fmt::print("\n");

                    data += lbytes;
                    addr += lbytes;
                    num_bytes -= lbytes;
                }
            }
            else
            {
                fmt::print("Could not read section's data.\n");
            }
        };

        for (const auto& shdr : section_header_table)
        {
            if (elf_s.read_section_name(shdr.name_offset, section_header_table[shdrstr_index]) == section_name)
            {
                if (!shdr.size || shdr.sec_type == shdr::SHT_NOBITS)
                {
                    fmt::print("Section '{}' has no data to dump.\n", section_name);
                    return;
                }

                dump_section(shdr);
                return;
            }
        }

        fmt::print("Section '{}' was not dumped because it does not exist.\n", section_name);
    }

    template<typename T>
    void
    hexdump_section(const elf::elf<T>& elf_s, u32 sh_name)
    {
        const auto& section_header_table { elf_s.get_shdr_table() };
        const u16 shdrstr_index { elf_s.get_file_header().shdr_str_index };

        if (shdrstr_index == shdr::SHN_UNDEF)
        {
            fmt::print("Can not retrieve section from name offset {} because the file doesn't have a section header string table\n", sh_name);
            return;
        }

        const std::string section_name { elf_s.read_section_name(sh_name, section_header_table[shdrstr_index]) };
        hexdump_section(elf_s, section_name);
    }

    template<typename STEntry>
    void
    output_st_entry(const STEntry& sym)
    {

    }

    template<typename Elf>
    void
    output_symtab(const Elf& elf_s)
    {
        // get symbol table
        // get number of entries
        // fmt::print("Symbol table '{}' contains {} entries:\n");
    }
}

#endif // ELF_INFO_ELF_PRINT_HH