#include <elf_info/elf_utils.hh>
#include <string>


namespace utils
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

    std::string_view
    ptype_tostr(phdr::phdr_type type)
    {
        using namespace phdr;

        if (type >= PT_LOOS && type <= PT_HIOS)
            return "OS specific";

        if (type >= PT_LOPROC && type <= PT_HIPROC)
            return "Proc. specific";

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
            case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
            case PT_GNU_STACK:    return "GNU_STACK";
            case PT_GNU_RELRO:    return "GNU_RELRO";
            case PT_GNU_PROPERTY: return "GNU_PROPERTY";
            default:              return "Unknown type";
        }
    }

    std::string
    phdr_flags_tostr(u32 flags)
    {
        if (!(flags & 7u)) return "No Flags";

        const u32 pf_msk_os   { 0x0FF00000 };
        const u32 pf_msk_proc { 0xF0000000 };

        if (flags & pf_msk_os)   return "OS Spec";
        if (flags & pf_msk_proc) return "Proc Spec";

        std::string perm_str;
        if (flags & (1u << 2u)) perm_str += 'R';
        if (flags & (1u << 1u)) perm_str += 'W';
        if (flags & 1u)         perm_str += 'E';

        return perm_str;
    }

    std::string
    shdr_flags_tostr(u64 flags)
    {
        using namespace shdr;

        if (flags & SHF_MASKOS)
            return "OS specific";

        if (flags & SHF_MASKPROC)
            return "Proc. specific";

        std::string attr(11, ' ');

        if (flags & SHF_WRITE)            attr[0] = 'W';
        if (flags & SHF_ALLOC)            attr[1] = 'A';
        if (flags & SHF_EXECINSTR)        attr[2] = 'X';
        if (flags & SHF_MERGE)            attr[3] = 'M';
        if (flags & SHF_STRINGS)          attr[4] = 'S';
        if (flags & SHF_INFO_LINK)        attr[5] = 'I';
        if (flags & SHF_LINK_ORDER)       attr[6] = 'L';
        if (flags & SHF_OS_NONCONFORMING) attr[7] = 'O';
        if (flags & SHF_GROUP)            attr[8] = 'G';
        if (flags & SHF_TLS)              attr[9] = 'T';
        if (flags & SHF_EXCLUDE)          attr[10] = 'E';

        return attr;
    }

    std::string
    stype_tostr(shdr::shdr_type type)
    {
        using namespace shdr;

        if (type >= SHT_LOOS && type <= SHT_HIOS)
            return "OS specific";

        if (type >= SHT_LOPROC && type <= SHT_HIPROC)
            return "Proc. specific";

        switch (type)
        {
            case SHT_NULL:		    return "NULL";
            case SHT_PROGBITS:		return "PROGBITS";
            case SHT_SYMTAB:		return "SYMTAB";
            case SHT_STRTAB:		return "STRTAB";
            case SHT_RELA:		    return "RELA";
            case SHT_HASH:		    return "HASH";
            case SHT_DYNAMIC:		return "DYNAMIC";
            case SHT_NOTE:		    return "NOTE";
            case SHT_NOBITS:		return "NOBITS";
            case SHT_REL:		    return "REL";
            case SHT_SHLIB:		    return "SHLIB";
            case SHT_DYNSYM:		return "DYNSYM";
            case SHT_INIT_ARRAY:	return "INIT_ARRAY";
            case SHT_FINI_ARRAY:	return "FINI_ARRAY";
            case SHT_PREINIT_ARRAY:	return "PREINIT_ARRAY";
            case SHT_GNU_HASH:		return "GNU_HASH";
            case SHT_GROUP:		    return "GROUP";
            case SHT_SYMTAB_SHNDX:	return "SYMTAB SHNDX";
            case SHT_NUM:           return "NUM";
            case SHT_LOPROC:        return "LOPROC";
            case SHT_LOUSER:        return "LOUSER";
            case SHT_HIUSER:        return "HIUSER";
            default:                return "No match found";
        }
    }
}
