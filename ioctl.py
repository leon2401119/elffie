from typedef import *

class pystream:
    __type_to_size_resolve_32 = {
        'ElfN_Addr'     : Elf32_Addr,
        'ElfN_Off'      : Elf32_Off,
        'ElfN_Section'  : Elf32_Section,
        'ElfN_Versym'   : Elf32_Versym,
        'ElfN_Half'     : Elf32_Half,
        'ElfN_Sword'    : Elf32_Sword,
        'ElfN_Word'     : Elf32_Word,
        'ElfN_Sxword'   : Elf32_Sxword,
        'ElfN_Xword'    : Elf32_Xword
    }
    __type_to_size_resolve_64 = {
        'ElfN_Addr'     : Elf64_Addr,
        'ElfN_Off'      : Elf64_Off,
        'ElfN_Section'  : Elf64_Section,
        'ElfN_Versym'   : Elf64_Versym,
        'ElfN_Half'     : Elf64_Half,
        'ElfN_Sword'    : Elf64_Sword,
        'ElfN_Word'     : Elf64_Word,
        'ElfN_Sxword'   : Elf64_Sxword,
        'ElfN_Xword'    : Elf64_Xword
    }

    def __init__(self, path = None):
        self.__path = path
        self.__bytearr = []
        self.__cursor = None
        self.endianness = None
        self.bitness = None
        self.__type_to_size_resolve = None

        if path:
            self.load(path)

    def set_endianness(self,endianness):
        self.endianness = endianness

    def set_bitness(self,bitness):
        if bitness == 1:
            self.__type_to_size_resolve = self.__type_to_size_resolve_32
        else:
            self.__type_to_size_resolve = self.__type_to_size_resolve_64
        self.bitness = bitness

    def load(self,path):
        self.__cursor = 0
        try:
            with open(path,'rb') as f:
                self.__bytearr = f.read()
        except FileNotFoundError:
            self.__bytearr = []

    def save(self,path):
        with open(path,'wb') as f:
            f.write(self.__bytearr)

    def seek(self,index):
        self.__cursor = index

    def getpos(self):
        return self.__cursor

    def read(self,length,offset=None,raw=False):
        endianness = 2 if raw else self.endianness

        if offset is not None:
            saved_cursor = self.__cursor
            self.seek(offset)

        if type(length) is str:
            length = self.__type_to_size_resolve[length]
        
        if type(length) is int and length < 0: # signed, not handled here, handled by hex_to_val
            length *= -1

        assert self.__cursor + length <= len(self.__bytearr), 'premature EOF'
        buf = self.__bytearr[self.__cursor:self.__cursor + length]
        buf = buf[::-1] if endianness == 1 else buf

        if offset is not None:
            self.seek(saved_cursor)
        else:
            self.__cursor += length

        return buf

    '''
    def read_addr(self,offset=None):
        length = 4 if self.bitness == 1 else 8
        return self.read(length,offset)
    '''

    def read_str(self,offset):
        if offset is not None:
            saved_cursor = self.__cursor
            self.seel(offset)

        buf = b''
        while True:
            c = self.read(1)
            if c == b'\x00':
                break
            buf += c

        if offset is not None:
            self.seek(saved_cursor)

        return buf.decode('ascii')
    
    def write(self):
        raise NotImplementedError()

    def write_addr(self):
        raise NotImplementedError()

    def write_str(self):
        raise NotImplementedError()


if __name__ == '__main__':
    stream = pystream('/home/yangck/elffie/hello')
    print(stream.read(4))

