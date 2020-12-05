#ifndef ELF_INFO_ELF_HH
#define ELF_INFO_ELF_HH

#include <string>
#include <fstream>
#include <vector>
#include <elf_info/integral_types.hh>
#include <elf_info/elf_structs.hh>


namespace elf
{
    ehdr::file_fmt_type
    get_fmt_type(std::ifstream& estream)
    {
        estream.seekg(ehdr::OFFSET_CLASS);

        char c;
        if (!estream.get(c))
            throw std::runtime_error("couldn't read format type\n");

        auto format = static_cast<ehdr::file_fmt_type>(c);

        if (format != ehdr::FMT32BIT && format != ehdr::FMT64BIT)
            throw std::runtime_error("unexpected format type\n");

        return format;

    }

    template<typename IntegerSize>
    std::string
    read_interp(std::ifstream& elf_stream, IntegerSize offset, IntegerSize size)
    {
        const auto prev_pos = elf_stream.tellg();
        elf_stream.seekg(offset);

        char* buffer = nullptr;

        try
        {
            buffer = new char[size];
            elf_stream.read(buffer, size);
            elf_stream.seekg(prev_pos);
        } catch (const std::bad_alloc& error)
        {
            elf_stream.seekg(prev_pos);
            return {};
        }

        std::string result(buffer, size);
        delete[] buffer;

        return result;
    }

    template<typename T>
    class elf
    {
        static_assert(std::is_same_v<T, u32> || std::is_same_v<T, u64>,
                 "Invalid type for ELF");

        using PhdrT = std::conditional_t<std::is_same_v<T, u64>,
                                         phdr::phdr64_data,
                                         phdr::phdr32_data>;

        using ShdrT = shdr::shdr_data<T>;

    public:
        // make a getter for this member
        std::ifstream stream;

    private:
        ehdr::ehdr_data<T> elf_header;
        std::vector<PhdrT> phdr_table;
        std::vector<ShdrT> shdr_table;

    public:
        explicit elf(std::ifstream&& estream) : stream(std::move(estream))
        {
            read_ehdr();
            read_phdr_table();
            read_shdr_table();
        }

        ~elf() = default;

        elf()           = delete;
        elf(const elf&) = delete;
        elf(elf&&)      = delete;

        elf& operator=(const elf&) = delete;
        elf& operator=(elf&&)      = delete;

        const ehdr::ehdr_data<T>&
        get_file_header() const
        {
            return elf_header;
        }

        const std::vector<PhdrT>&
        get_phdr_table() const
        {
            return phdr_table;
        }

        const std::vector<ShdrT>&
        get_shdr_table() const
        {
            return shdr_table;
        }

        void
        read_ehdr()
        {
            stream.seekg(ehdr::EHDR_POS);
            stream.read(reinterpret_cast<char*>(&elf_header), sizeof elf_header);

            if (!stream)
                throw std::runtime_error("couldn't read ELF header properly\n");

            if (elf_header.ident_bytes[0] != 0x7f ||
                elf_header.ident_bytes[1] != 'E'  ||
                elf_header.ident_bytes[2] != 'L'  ||
                elf_header.ident_bytes[3] != 'F')
            {
                throw std::runtime_error("mismatch in ELF file signature.\n");
            }
        }

        void
        read_phdr_table()
        {
            phdr_table.reserve(elf_header.phdr_amount);

            stream.seekg(elf_header.phdr_offset);

            for (u16 ph_index = 0; ph_index < elf_header.phdr_amount; ++ph_index)
            {
                PhdrT curr_phdr {};
                if (!stream.read(reinterpret_cast<char*>(&curr_phdr), sizeof(PhdrT)))
                    throw std::runtime_error("couldn't read program headers.");

                phdr_table.push_back(curr_phdr);
            }
        }

        void
        read_shdr_table()
        {
            shdr_table.reserve(elf_header.shdr_amount);

            stream.seekg(elf_header.shdr_offset);

            for (u16 sh_index = 0; sh_index < elf_header.shdr_amount; ++sh_index)
            {
                ShdrT curr_shdr {};
                if (!stream.read(reinterpret_cast<char*>(&curr_shdr), sizeof(ShdrT)))
                    throw std::runtime_error("couldn't read section headers");

                shdr_table.push_back(curr_shdr);
            }
        }
    };
}

#endif //ELF_INFO_ELF_HH
