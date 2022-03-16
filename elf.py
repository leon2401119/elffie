from enum import Enum
from utils import *
import structs

class ELF:
    def __init__(self):
        self.bytearr = None
        self.cursor = 0
        self.endianness = 'Big Endian' # For correctly reading magic

    def dissect(self,bytearr):
        self.bytearr = bytearr
        self.read_eh()

    def seek(self,index):
        self.cursor = index

    def read(self,bits):
        assert self.cursor + bits <= len(self.bytearr), 'premature EOF'
        output = self.bytearr[self.cursor:self.cursor+bits]
        self.cursor += bits
        return output if self.endianness == 'Big Endian' else output[::-1]

    def summarize(self):
        #FIXME : ugly af
        print('{} {} File for {} ({}) running {}'.format(
            structs.ELF_BIT_FORMAT[self.bit_format],
            structs.ELF_FILE_TYPE[self.file_type],
            structs.ELF_ISA[self.isa],
            structs.ELF_ENDIANNESS[self.endianness],
            structs.ELF_OS_ABI[self.os_abi])
        )

    def read_eh(self):
        self.seek(0)
        magic = self.read(4)
        assert magic == b'\x7f' + bytes('ELF','ASCII'), 'file is not ELF'

        self.bit_format = hex_to_dec(self.read(1))
        assert self.bit_format in [1,2], 'unrecognized bit format'

        self.endianness = hex_to_dec(self.read(1))
        assert self.endianness in [1,2], 'unrocognized endianness'

        self.elf_version = hex_to_dec(self.read(1))

        self.os_abi = hex_to_dec(self.read(1))
        assert self.os_abi in structs.ELF_OS_ABI.keys(), 'unrecognized OS'

        self.abi_version = hex_to_dec(self.read(1))

        assert self.read(7) == b'\x00\x00\x00\x00\x00\x00\x00', 'abnormal padding'

        self.file_type = hex_to_dec(self.read(2))
        assert self.file_type in structs.ELF_FILE_TYPE.keys(), 'unrecognized ELF type'

        self.isa = hex_to_dec(self.read(2))
        assert self.isa in structs.ELF_ISA.keys()

