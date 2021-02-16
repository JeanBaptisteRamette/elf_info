#ifndef ELF_INFO_ELF_TYPES_HH
#define ELF_INFO_ELF_TYPES_HH

#include <elf_info/integral_types.hh>


namespace ehdr
{
    constexpr u8 EHDR_POS = 0;
    constexpr u8 IDENT_SIZE         = 16;
    constexpr u8 OFFSET_CLASS      = 4;
    constexpr u8 OFFSET_DATA       = 5;
    constexpr u8 OFFSET_VERSION    = 6;
    constexpr u8 OFFSET_OS_ABI     = 7;
    constexpr u8 OFFSET_ABIVERSION = 8;

    enum file_type : u16
    {
        ET_NONE   = 0x0,
        ET_REL    = 0x1,
        ET_EXEC   = 0x2,
        ET_DYN    = 0x3,
        ET_CORE   = 0x4,
        ET_LOOS   = 0xFE00,
        ET_HIOS   = 0xFEFF,
        ET_LOPROC = 0xFF00,
        ET_HIPROC = 0xFFFF
    };

    enum file_fmt_type : u8
    {
        FMT32BIT = 0x01,
        FMT64BIT = 0x02
    };

    enum endianness_type : u8
    {
        ELFDATA2LSB = 0x01,
        ELFDATA2MSB = 0x02
    };

    template<typename SizeType>
    struct ehdr_data
    {
        u8  ident_bytes[IDENT_SIZE];
        file_type type;           // 1 = relocatable, 2 = executable, 3 = shared, 4 = core
        u16 target;               // target machine
        u32 version;              // ELF file version
        SizeType entry;           // program entry position
        SizeType phdr_offset;     // program header offset in bytes
        SizeType shdr_offset;     // section header offset in bytes
        u32 flags;                // unused flags for x86 ELF
        u16 ehdr_size;            // size of this header
        u16 phdr_entry_size;      // size of a program header table entry
        u16 phdr_amount;          // number of entries in the program header table
        u16 shdr_entry_size;      // size of a section header table entry
        u16 shdr_amount;          // number of entries in the section header table
        u16 shdr_str_index;       // index of the shdr entry that contains the section names.
    };
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

    // flags position differs
    struct phdr32_data
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

    struct phdr64_data
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
}

namespace shdr
{
    constexpr u8 SHN_UNDEF = 0;
    constexpr u16 SHN_XINDEX = 0xFFFF;

    enum attribute : u32
    {
        SHF_WRITE = 0x1,
        SHF_ALLOC = 0x2,
        SHF_EXECINSTR = 0x4,
        SHF_MERGE = 0x10,
        SHF_STRINGS = 0x20,
        SHF_INFO_LINK = 0x40,
        SHF_LINK_ORDER = 0x80,
        SHF_OS_NONCONFORMING = 0x100,
        SHF_GROUP = 0x200,
        SHF_TLS = 0x400,
        SHF_EXCLUDE = 0x80000000,
        SHF_MASKOS = 0x0FF00000,
        SHF_MASKPROC = 0xF0000000,
    };

    enum shdr_type : u32
    {
        SHT_NULL          = 0x0,
        SHT_PROGBITS      = 0x1,
        SHT_SYMTAB        = 0x2,
        SHT_STRTAB        = 0x3,
        SHT_RELA          = 0x4,
        SHT_HASH          = 0x5,
        SHT_DYNAMIC       = 0x6,
        SHT_NOTE          = 0x7,
        SHT_NOBITS        = 0x8,
        SHT_REL           = 0x9,
        SHT_SHLIB         = 0x0A,
        SHT_DYNSYM        = 0x0B,
        SHT_INIT_ARRAY    = 0x0E,
        SHT_FINI_ARRAY    = 0x0F,
        SHT_PREINIT_ARRAY = 0x10,
        SHT_GROUP         = 0x11,
        SHT_SYMTAB_SHNDX  = 0x12,
        SHT_NUM           = 0x13,
        SHT_LOOS          = 0x60000000,
        SHT_GNU_HASH      = 0x6FFFFFF6,
        SHT_HIOS          = 0x6FFFFFFF,
        SHT_LOPROC        = 0x70000000,
        SHT_HIPROC        = 0x7FFFFFFF,
        SHT_LOUSER        = 0x80000000,
        SHT_HIUSER        = 0xFFFFFFFF
    };

    template<typename SizeType>
    struct shdr_data
    {
        u32 name_offset;       // offset to a string in the .shstrtab section that represents the name of this section
        shdr_type sec_type;    // section header type
        SizeType  flags;       // section attribute
        SizeType  vaddr;       // virtual address of the section in memory, for the sections that are loaded
        SizeType  offset;      // offset of the section in the file image
        SizeType  size;        // size in bytes of the section in the file image, may be 0
        u32       link;        // section index of an assiociated section
        u32       ex_info;     // extra info about the section
        SizeType  addr_algn;   // required alignment of the section
        SizeType  entry_size;  //size in bytes of each entry
    };
}


#endif //ELF_INFO_ELF_TYPES_HH
