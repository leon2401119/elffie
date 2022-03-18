from enum import Enum
from utils import *
import dics
from section import *
from segment import *
try:
    from iced_x86 import *
except ImportError:
    print('Disassembler not found, run "pip install iced-x86" and try again')


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
        self.__read_program_headers()
        self.__init_sec2seg_mapping()
        self.disassemble_section()
        #self.disassemble_section('.text')


    def seek(self,index):
        self.__cursor = index


    def read(self,byte,offset=None,raw=False):
        endianness = 2 if raw else self.endianness

        if offset is not None:
            saved_cursor = self.__cursor
            self.seek(offset)

        assert self.__cursor + byte <= len(self.bytearr), 'premature EOF'
        buf = self.bytearr[self.__cursor:self.__cursor+byte]
        buf = buf[::-1] if endianness == 1 else buf

        if offset is not None:
            self.seek(saved_cursor)
        else:
            self.__cursor += byte

        return buf


    def read_addr(self,offset=None):
        byte = 4 if self.bit_format == 1 else 8
        return self.read(byte,offset,False)


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
        self.sections = Sections()

        sections_list = []
        for idx in range(self.section_header_num):
            if not idx:
                section_header = SectionHeader()
                self.read(self.section_header_size)
            else:
                section_header = self.__read_section_header()
            
            sections_list.append(section_header)

        for idx, section in enumerate(sections_list):
            if not idx: # first section header is always empty
                shname = 'null'
            else:
                shname = self.read_str(sections_list[self.section_header_name_section_index].offset + section.name)
            
            self.sections.add_section(shname,section)


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
        return sh


    def __read_program_headers(self):
        self.seek(self.program_header_table_offset)
        self.segments = []

        for idx in range(self.program_header_num):
            program_header = self.__read_program_header()
            self.segments.append(program_header)


    def __read_program_header(self):
        ph = ProgramHeader()

        ph.type = hex_to_dec(self.read(4))
        
        if self.bit_format == 2:
            ph.flags = hex_to_dec(self.read(4))

        ph.offset = hex_to_dec(self.read_addr())
        ph.vaddr = hex_to_dec(self.read_addr())
        ph.paddr = hex_to_dec(self.read_addr())
        ph.filesize = hex_to_dec(self.read_addr())
        ph.memsize = hex_to_dec(self.read_addr())

        if self.bit_format == 1:
            ph.flags = hex_to_dec(self.read(4))

        ph.align = hex_to_dec(self.read_addr())

        self.read(self.program_header_size - 32) if self.bit_format == 1 else self.read(self.program_header_size - 56)
        return ph


    def __init_sec2seg_mapping(self): # establish a dictionary mapping between 'section name' and 'segment num'
        pass


    def __format_inst_hex_repr(self,bytes_str):
        new_str = ''
        trailing_zeros = 0
        rev_bytes_str = bytes_str[::-1]
        for i in range(len(bytes_str)//2):
            if rev_bytes_str[2*i:2*i+2] == '00':
                trailing_zeros += 1
            else:
                break

        for i in range(0,len(bytes_str)-trailing_zeros*2,2):
            new_str += bytes_str[i:i+2]
            new_str += ' '

        return new_str
            

    def disassemble_section(self,section_name = None):
        section_names = []
        if section_name is not None:
            section_names.append(section_name)
        else:
            for section_name in self.sections.keys():
                section = self.sections[section_name]
                if section.is_executable():
                    section_names.append(section_name)
                    #print(f'{section_name}')
       
        for section_name in section_names:
            try:
                section = self.read(self.sections[section_name].size, self.sections[section_name].offset, raw = True)
                vaddr = self.sections[section_name].addr
            except KeyError as e:
                print(f'Cannot find section {section_name}')

            print(f'Disassembly of section {section_name}:\n')
            self.__disassemble(section,vaddr)
            print('')


    def __disassemble(self,raw_bytes,start_EIP):
        # TODO : after reading symbol table & string table, create a vaddr -> func name mapping, then for every inst.ip in the mapping, we can print function name

        decoder = Decoder(32 if self.bit_format == 1 else 64, raw_bytes, ip=start_EIP)
        formatter = Formatter(FormatterSyntax.INTEL)

        for inst in decoder:
            disasm = f"{inst:gx}"
            #disasm = formatter.format(inst)
            start_index = inst.ip - start_EIP
            bytes_str = raw_bytes[start_index:start_index + inst.len].hex()#.upper()
            bytes_str = self.__format_inst_hex_repr(bytes_str)
            if self.bit_format == 1:
                print(f"    0x{inst.ip:04x}   {bytes_str:24} {disasm}")
            else:
                print(f"    0x{inst.ip:08x}   {bytes_str:24} {disasm}")

