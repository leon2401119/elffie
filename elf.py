from enum import Enum
from utils import *
import dics
from section import *

class ELF:
    def __init__(self):
        self.bytearr = None
        self.cursor = 0
        self.endianness = 2 # For correctly reading magic

        # internal
        self.__shstr_section_offset = None
        self.__shstr_section_size = None


    def dissect(self,bytearr):
        self.bytearr = bytearr
        self.__read_elf_header()
        self.__read_section_headers()


    def seek(self,index):
        self.__cursor = index


    def read(self,byte,offset=None):
        if offset is not None:
            saved_cursor = self.__cursor
            self.seek(offset)

        assert self.__cursor + byte <= len(self.bytearr), 'premature EOF'
        output = self.bytearr[self.__cursor:self.__cursor+byte]
        
        if offset is not None:
            self.seek(saved_cursor)
        else:
            self.__cursor += byte
        
        return output if self.endianness == 2 else output[::-1]


    def read_addr(self,offset=None):
        byte = 4 if self.bit_format == 1 else 8
        return self.read(byte,offset)


    def read_str(self,offset=None):
        if offset is not None:
            saved_cursor = self.__cursor
            self.seek(offset)

        buf = b''
        while True:
            c = self.read(1)
            if c == b'\x00':
                break
            buf += c

        if offset is not None:
            self.seek(saved_cursor)

        return buf.decode('ASCII')


    def summarize(self):
        #FIXME : ugly af
        print('{} {} File for {} ({}) running {}'.format(
            dics.ELF_BIT_FORMAT[self.bit_format],
            dics.ELF_FILE_TYPE[self.file_type],
            dics.ELF_ISA[self.isa],
            dics.ELF_ENDIANNESS[self.endianness],
            dics.ELF_OS_ABI[self.os_abi])
        )

        print(f'Total of {self.section_header_num} sections, {self.program_header_num} segments')

        if self.bit_format == 1:
            print('Entry at 0x{:04x}'.format(self.entry))
        else:
            print('Entry at 0x{:08x}'.format(self.entry))


    def __read_elf_header(self):
        # FIXME : the abundance of hex_to_dec pains my eyes, find a fking better way (like incorporating an optinal raw arg into read functions)

        self.seek(0)
        magic = self.read(4)
        assert magic == b'\x7f' + bytes('ELF','ASCII'), 'file is not ELF'

        self.bit_format = hex_to_dec(self.read(1))
        assert self.bit_format in [1,2], 'unrecognized bit format'

        self.endianness = hex_to_dec(self.read(1))
        assert self.endianness in [1,2], 'unrocognized endianness'

        self.elf_version = hex_to_dec(self.read(1))

        self.os_abi = hex_to_dec(self.read(1))
        assert self.os_abi in dics.ELF_OS_ABI.keys(), 'unrecognized OS'

        self.abi_version = hex_to_dec(self.read(1))

        assert self.read(7) == b'\x00\x00\x00\x00\x00\x00\x00', 'abnormal padding'

        self.file_type = hex_to_dec(self.read(2))
        assert self.file_type in dics.ELF_FILE_TYPE.keys(), 'unrecognized ELF type'

        self.isa = hex_to_dec(self.read(2))
        assert self.isa in dics.ELF_ISA.keys()

        self.elf_version_dup = hex_to_dec(self.read(4))

        self.entry = hex_to_dec(self.read_addr())
        self.program_header_table_offset = hex_to_dec(self.read_addr())
        self.section_header_table_offset = hex_to_dec(self.read_addr())
        
        self.flags = hex_to_dec(self.read(4)) # Wiki : Interpretation of this field depends on the target architecture.

        self.elf_header_size = hex_to_dec(self.read(2))
        self.program_header_size = hex_to_dec(self.read(2))
        self.program_header_num = hex_to_dec(self.read(2))
        self.section_header_size = hex_to_dec(self.read(2))
        self.section_header_num = hex_to_dec(self.read(2))

        self.section_header_name_section_index = hex_to_dec(self.read(2))

        self.seek(0 + self.elf_header_size)

    
    def __read_section_headers(self):
        self.seek(self.section_header_table_offset)

        # FIXME : define sections as a type, overload both [] and {} operator to behave like simple indexing and searching with section name
        self.sections = {}
        self.sections_list = []
        for idx in range(self.section_header_num):
            if not idx:
                section_header = SectionHeader()
                self.read(self.section_header_size)
            else:
                #section_name, section_header = self.__read_section_header()
                #self.sections[section_name] = section_header
                section_header = self.__read_section_header()
            
            self.sections_list.append(section_header)

        for idx, section in enumerate(self.sections_list):
            if not idx:
                shname = 'null'
            else:
                shname = self.read_str(self.sections_list[self.section_header_name_section_index].offset + section.name)
            self.sections[shname] = section


    def __read_section_header(self):
        sh = SectionHeader()

        sh.name = hex_to_dec(self.read(4))
        sh.type = hex_to_dec(self.read(4))
        sh.flags = hex_to_dec(self.read_addr())
        sh.addr = hex_to_dec(self.read_addr())
        sh.offset = hex_to_dec(self.read_addr())
        sh.size = hex_to_dec(self.read_addr())
        sh.link = hex_to_dec(self.read(4))
        sh.info = hex_to_dec(self.read(4))
        sh.align = hex_to_dec(self.read_addr())
        sh.entry_size = hex_to_dec(self.read_addr())

        # digest the paddings
        self.read(self.section_header_size - 40) if self.bit_format == 1 else self.read(self.section_header_size - 64)

        #return shname, sh
        return sh
