ELF_BIT_FORMAT = {
    1 : '32-bit',
    2 : '64-bit'
}

ELF_ENDIANNESS = {
    1 : 'Little Endian',
    2 : 'Big Endian'
}

ELF_OS_ABI = {
    0 : 'System V',
    2 : 'NetBSD',
    3 : 'Linux',
    6 : 'Solaris',
    9 : 'FreeBSD'
}

ELF_FILE_TYPE = {
    0 : 'Unknown',
    1 : 'Relocatable',
    2 : 'Executable',
    3 : 'Shared',
    4 : 'Core Dump'
}

ELF_ISA = {
    0x00 : 'Unknown',
    0x02 : 'SPARC',
    0x03 : 'x86',
    0x04 : 'Motorola 68000',
    0x05 : 'Motorola 88000',
    0x08 : 'MIPS',
    0x28 : 'Aarch32',
    0x32 : 'IA-64',
    0x3E : 'x86-64',
    0xB7 : 'Aarch64',
    0xF3 : 'RISC-V'
}
