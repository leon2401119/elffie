'''
    Basic C types, and their respective size
'''
char             = -1
uchar            = 1
int16_t          = -2
uint16_t         = 2
int32_t          = -4
uint32_t         = 4
int64_t          = -8
uint64_t         = 8


'''
    Extended types defined for ELF, ElfN prefixed sizes will be dynamically resolved by the pystream object
'''
Elf32_Addr       = uint32_t
Elf64_Addr       = uint64_t
ElfN_Addr        = 'ElfN_Addr'

Elf32_Off        = uint32_t
Elf64_Off        = uint64_t
ElfN_Off         = 'ElfN_Off'

Elf32_Section    = uint16_t
Elf64_Section    = uint16_t
ElfN_Section     = 'ElfN_Section'

Elf32_Versym     = uint16_t
Elf64_Versym     = uint16_t
ElfN_Versym      = 'ElfN_Versym'

Elf_Byte = uchar

Elf32_Half       = uint16_t
Elf64_Half       = Elf32_Half
ElfN_Half        = 'ElfN_Half'

Elf32_Sword      = int32_t
Elf64_Sword      = Elf32_Sword
ElfN_Sword       = 'ElfN_Sword'

Elf32_Word       = uint32_t
Elf64_Word       = Elf32_Word
ElfN_Word        = 'ElfN_Word'

Elf32_Sxword     = int64_t
Elf64_Sxword     = Elf32_Sxword
ElfN_Sxword      = 'ElfN_Sxword'

Elf32_Xword      = uint64_t
Elf64_Xword      = Elf32_Xword
ElfN_Xword       = 'ElfN_Xword'

