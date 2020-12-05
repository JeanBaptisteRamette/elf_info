#include <unistd.h>
#include <fmt/core.h>
#include <elf_info/elf.hh>
#include <elf_info/elf_print.hh>


void
help(const char* program_name)
{
    fmt::print("Usage: {} -f <file> <options>\n", program_name);

    const std::string options = "Options:\n"
                                "  -f     ELF file\n"
                                "  -h     Display file header\n"
                                "  -l     Display file program headers\n"
                                "  -s     Display file section headers\n";

    fmt::print(options);
}

template<typename T>
void
output_file_structures(elf::elf<T>& elf_s,
                       bool opt_header,
                       bool opt_program_headers,
                       bool opt_section_headers)
{
    if (opt_header)
        print::output_ehdr_structure(elf_s.get_file_header());

    if (opt_program_headers)
        print::output_phdr_table(elf_s);

    if (opt_section_headers)
        print::output_shdr_table(elf_s.get_shdr_table());
}

int
main(int argc, char* argv[])
{
    if (argc == 1)
    {
        help(argv[0]);
        return EXIT_SUCCESS;
    }

    std::string file_name;
    bool opt_header {};
    bool opt_program_headers {};
    bool opt_section_headers {};

    int c;
    while ((c = getopt(argc, argv, "hlsf:")) != -1)
    {
        switch (c)
        {
            case 'h': opt_header = true;          break;
            case 'l': opt_program_headers = true; break;
            case 's': opt_section_headers = true; break;
            case 'f': file_name = optarg;         break;
            default:                              break;
        }
    }

    if (file_name.empty())
    {
        fmt::print(stderr, "-f argument required");
        help(argv[0]);
        return EXIT_FAILURE;
    }

    for (auto index = optind; index < argc; ++index)
        fmt::print("[WARNING]: Non-option argument {}\n", argv[index]);

    std::ifstream elf_stream(file_name, std::ios::binary | std::ios::in);
    if (!elf_stream)
    {
        fmt::print(stderr, "[ERROR]: couldn't open file '{}'", file_name);
        return EXIT_FAILURE;
    }

    ehdr::file_fmt_type fmt;

    try
    {
        fmt = elf::get_fmt_type(elf_stream);
    } catch (const std::runtime_error& error)
    {
        fmt::print(error.what());
        return EXIT_FAILURE;
    }

    // TODO: catch errors when creating elf_file
    if (fmt == ehdr::file_fmt_type::FMT64BIT)
    {
        elf::elf<u64> elf_file(std::move(elf_stream));
        output_file_structures(elf_file, opt_header, opt_program_headers, opt_section_headers);
    } else
    {
        elf::elf<u32> elf_file(std::move(elf_stream));
        output_file_structures(elf_file, opt_header, opt_program_headers, opt_section_headers);
    }

    return EXIT_SUCCESS;
}