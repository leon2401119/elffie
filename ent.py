from typedef import *
from ioctl import pystream
from inspect import isclass
from utils import hex_to_val

class Entry:
    #attrs32 = None       # list of attribute names in order for 32-bit structures
    #attrs64 = None       # list of attribute names in order for 64-bit structures
    attrs = None
    attr_to_type = None   # dict for attribute name to its type with types listed in typedef.py

    def __init__(self):
        ''' 
            Any initialization of Entry() base class or subclasses that does not overwrite self.__attr_to_offset dicts will trigger exception
        '''
        #assert self.__attr_to_position_32, 'attr_to_offset_32 undefined'
        #assert self.__attr_to_position_64, 'attr_to_offset_64 undefined'
        #assert self.__attr_to_type, 'attr_to_type  undefined'

        #self.__raw = b''
        self.__offset = None
        self.__size = None
        self.__dirty = False
        self.__content = []

    def read(self,pys):
        self.__path = pys.getpath()
        self.__offset = pys.getpos()

        for field in self.attrs:
            attr_type = self.attr_to_type[field]

            if isclass(attr_type):
                self.__dict__[field] = attr_type()
                self.__dict__[field].read(pys)

            else:
                byte_arr = pys.read(attr_type)
                self.__dict__[field] = hex_to_val(byte_arr,attr_type)

    def write(self,pys): # pure virtual
        raise NotImplementedError()

    # FIXME : raw bytes should be dynamically constructed, not stored (to maintain consistency with various APIs)
    def raw(self):
        raise NotImplementedError()
	
    def __getitem__(self,slc):
        pass
	#return self.__raw[slc]

    def __setitem__(self,idx,val):
        pass
	#self.__raw[idx] = val

    def __getattr__(self,attr:str):
        try:
            return self.__dict__[attr]
        except KeyError:
            return None

    def __len__(self):
        return self.__size


class ELF(Entry):
    def __init__(self, path = None):
        super().__init__()

        self.pys = pystream(path)
        if path:
            self.read(self.pys)

    def read(self,pys):
        self.eh = EH()
        self.eh.read(pys)

        pys.seek(self.eh.phoff)

        self.phs = []
        for _ in range(self.eh.phnum):
            ph = PH(self.eh.ident.__dict__['class'])
            ph.read(pys)
            # assert ph size is eh.phentsize?
            self.phs.append(ph)

        pys.seek(self.eh.shoff)

        self.shs = []
        for _ in range(self.eh.shnum):
            sh = SH(self.eh.ident.__dict__['class'])
            sh.read(pys)
            self.shs.append(sh)

    def write(self,pys):
        raise NotImplementedError()

    def __getattr__(self,attr):
        ret_val = super().__getattr__(attr)
        if ret_val is None:
            print(f'ELF has no attribute named {attr}')
        return ret_val


class EH(Entry):

    class IDENT(Entry): 
        # 32/64-bit is unknown while parsing ident, so it is indistinguishable here
        # the only structure parsable without the info of bitness and endianness
        attrs = [
            'mag0',
            'mag1',
            'mag2',
            'mag3',
            'class',
            'data',
            'version',
            'osabi',
            'abiversion',
            'padding'
        ]
        attr_to_type = {attr : uchar for attr in attrs[:-1]}
        attr_to_type['padding'] = 7

        def __init__(self):
            super().__init__()

        def read(self,pys):
            super().read(pys)

            pys.set_bitness(self.__dict__['class'])
            pys.set_endianness(self.__dict__['data'])

        def __getattr__(self,attr):
            ret_val = super().__getattr__(attr)
            if ret_val is None:
                print(f'ELF Header IDENT has no attribute named {attr}')
            return ret_val

    attrs = [
        'ident',
        'type',
        'machine',
        'version',
        'entry',
        'phoff',
        'shoff',
        'flags',
        'ehsize',
        'phentsize',
        'phnum',
        'shentsize',
        'shnum',
        'shstrndx'
    ]
    attr_to_type = {
        'ident'     :      IDENT,
        'type'      :   uint16_t,
        'machine'   :   uint16_t,
        'version'   :   uint32_t,
        'entry'     :  ElfN_Addr,
        'phoff'     :   ElfN_Off,
        'shoff'     :   ElfN_Off,
        'flags'     :   uint32_t,
        'ehsize'    :   uint16_t,
        'phentsize' :   uint16_t,
        'phnum'     :   uint16_t,
        'shentsize' :   uint16_t,
        'shnum'     :   uint16_t,
        'shstrndx'  :   uint16_t
    }

    def __init__(self):
        super().__init__()

    def read(self,pys):
        super().read(pys)

    def write(self,pys):
        raise NotImplementedError()

    def __getattr__(self,attr):
        ret_val = super().__getattr__(attr)
        if ret_val is None:
            print(f'ELF Header has no attribute named {attr}')
        return ret_val


class SH(Entry):
    attrs = [
        'name',
        'type',
        'flags',
        'addr',
        'offset',
        'size',
        'link',
        'info',
        'addralign',
        'entsize'
    ]
    attr_to_type32 = {
        'name'      : uint32_t,
        'type'      : uint32_t,
        'flags'     : uint32_t,
        'addr'      : ElfN_Addr,
        'offset'    : ElfN_Off,
        'size'      : uint32_t,
        'link'      : uint32_t,
        'info'      : uint32_t,
        'addralign' : uint32_t,
        'entsize'   : uint32_t
    }
    attr_to_type64 = {
        'name'      : uint32_t,
        'type'      : uint32_t,
        'flags'     : uint64_t,
        'addr'      : ElfN_Addr,
        'offset'    : ElfN_Off,
        'size'      : uint64_t,
        'link'      : uint32_t,
        'info'      : uint32_t,
        'addralign' : uint64_t,
        'entsize'   : uint64_t
    }

    def __init__(self, bitness):
        super().__init__()
        self.bitness = bitness
        if self.bitness == 1:
            self.attr_to_type = self.attr_to_type32
        elif self.bitness == 2:
            self.attr_to_type = self.attr_to_type64
        else:
            raise
    
    def read(self,pys):
        super().read(pys)

    def write(self,pys):
        raise NotImplementedError()

    def __getattr__(self,attr):
        ret_val = super().__getattr__(attr)
        if ret_val is None:
            print(f'Section Header has no attribute named {attr}')
        return ret_val


class PH(Entry):
    attrs32 = [
        'types',
        'flags',
        'offset',
        'vaddr',
        'paddr',
        'filesz',
        'memsz',
        'align',
    ]
    attrs64 = [
        'types',
        'offset',
        'vaddr',
        'paddr',
        'filesz',
        'memsz',
        'flags',
        'align',
    ]
    attr_to_type32 = {
        'types'     : uint32_t,
        'offset'    : ElfN_Off,
        'vaddr'     : ElfN_Addr,
        'paddr'     : ElfN_Addr,
        'filesz'    : uint32_t,
        'memsz'     : uint32_t,
        'flags'     : uint32_t,
        'align'     : uint32_t
    }
    attr_to_type64 = {
        'types'     : uint32_t,
        'offset'    : ElfN_Off,
        'vaddr'     : ElfN_Addr,
        'paddr'     : ElfN_Addr,
        'filesz'    : uint64_t,
        'memsz'     : uint64_t,
        'flags'     : uint32_t,
        'align'     : uint64_t
    }

    def __init__(self, bitness):
        super().__init__()
        self.bitness = bitness
        if self.bitness == 1:
            self.attrs = self.attrs32
            self.attr_to_type = self.attr_to_type32
        elif self.bitness == 2:
            self.attrs = self.attrs64
            self.attr_to_type = self.attr_to_type64
        else:
            raise
    
    def read(self,pys):
        super().read(pys)

    def write(self,pys):
        raise NotImplementedError()

    def __getattr__(self,attr):
        ret_val = super().__getattr__(attr)
        if ret_val is None:
            print(f'Program Header has no attribute named {attr}')
        return ret_val


if __name__ == '__main__':
    pys = pystream('./hello')
    pys.set_endianness(1)
    pys.set_bitness(2)
    elf_header = EH()
    elf_header.read(pys)
