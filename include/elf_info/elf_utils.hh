#ifndef ELF_INFO_ELF_UTILS_HH
#define ELF_INFO_ELF_UTILS_HH

#include <string>
#include <elf_info/elf_types.hh>

namespace utils
{
    template<typename Integer>
    char
    digit_count(Integer number)
    {
        static_assert(std::is_integral_v<decltype(number)>);

        char digits { 0 };
        for (;number; number /= 10, digits++);
        return digits;
    }

    const char*
    file_type_to_str(ehdr::file_type type);

    const char*
    target_to_str(u16 tar_byte);

    std::string_view
    ptype_tostr(phdr::phdr_type type);

    std::string
    phdr_flags_tostr(u32 flags);

    std::string
    shdr_flags_tostr(u64 flags);

    std::string
    stype_tostr(shdr::shdr_type type);
}

#endif //ELF_INFO_ELF_UTILS_HH
