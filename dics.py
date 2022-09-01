ELF_BIT_FORMAT = {
    1 : '32-bit',
    2 : '64-bit'
}

ELF_ENDIANNESS = {
    1 : 'Little Endian',
    2 : 'Big Endian'
}

ELF_OS_ABI = {
    0x0 : 'System V',
    0x2 : 'NetBSD',
    0x3 : 'Linux',
    0x6 : 'Solaris',
    0x9 : 'FreeBSD',
    0xC : 'OpenBSD'
}

ELF_FILE_TYPE = {
    0x0 : 'Unknown',
    0x1 : 'Relocatable',
    0x2 : 'Executable',
    0x3 : 'Shared',
    0x4 : 'Core Dump'
}

ELF_ISA = {
    0x00 : 'Unknown',
    0x02 : 'SPARC',
    0x03 : 'x86 (i386)',
    0x04 : 'Motorola M68k',
    0x05 : 'Motorola M88k',
    0x08 : 'MIPS',
    0x14 : 'PowerPC',
    0x15 : 'PowerPC (64-bit)',
    0x28 : 'ARM (aarch32)',
    0x32 : 'IA-64',
    0x3E : 'x86-64 (amd-64)',
    0xB7 : 'ARM (aarch64)',
    0xF3 : 'RISC-V'
}
