from typedef import *
from ioctl import pystream
from inspect import isclass
from utils import hex_to_val

class Entry:
    __attr_to_position_32 = None
    __attr_to_position_64 = None
    __attr_to_type = None

    def __init__(self):
        ''' 
            Any initialization of Entry() base class or subclasses that does not overwrite self.__attr_to_offset dicts will trigger exception
        '''
        #assert self.__attr_to_position_32, 'attr_to_offset_32 undefined'
        #assert self.__attr_to_position_64, 'attr_to_offset_64 undefined'
        #assert self.__attr_to_type, 'attr_to_type  undefined'

        self.__raw = b''
        self.__offset = None
        self.__size = None
        self.__dirty = False
        self.__content = []

    def read(self,pys): # pure virtual
        raise NotImplementedError()

    def write(self,pys): # pure virtual
        raise NotImplementedError()

    #def raw(self):
    #    return self.__raw
	
    def __getitem__(self,slc):
        pass
	#return self.__raw[slc]

    def __setitem__(self,idx,val):
        pass
	#self.__raw[idx] = val

    def __getattr__(self,attr:str):
        raise NotImplementedError()

    def __len__(self):
        return self.__size


class EH(Entry):

    class IDENT(Entry):
        __attr_to_position = [
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
        __attr_to_type = {attr : uchar for attr in __attr_to_position[:-1]}
        __attr_to_type['padding'] = 7

        def __init__(self):
            super().__init__()

        def read(self,pys):
            self.__offset = pys.getpos()
            self.__pys = pys

            for field in self.__attr_to_position:
                attr_type = self.__attr_to_type[field]
                byte_arr = pys.read(attr_type)
                self.__dict__[field] = hex_to_val(byte_arr,attr_type)

        def __getattr__(self,attr):
            try:
                return self.__dict__[attr]
            except KeyError:
                print(f'Elf header has no attribute named {attr}')
                return None



    __attr_to_position_32 = [
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
    __attr_to_position_64 = __attr_to_position_32
    
    __attr_to_type = {
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

    def read(self,pys): # read the content of the elf header
        # save the file offset for lazy read
        self.__offset = pys.getpos()
        self.__pys = pys

        if pys.bitness == 1:
            self.__attr_to_position = self.__attr_to_position_32
        elif pys.bitness == 2:
            self.__attr_to_position = self.__attr_to_position_64

        for field in self.__attr_to_position:
            attr_type = self.__attr_to_type[field]

            if isclass(attr_type):
                self.__dict__[field] = attr_type()
                self.__dict__[field].read(pys)

            else:
                byte_arr = pys.read(attr_type)
                self.__dict__[field] = hex_to_val(byte_arr,attr_type)


    def write(self,pys):
        pass

    def __getattr__(self,attr):
        try:
            return self.__dict__[attr]
        except KeyError:
            print(f'Elf header has no attribute named {attr}')
            return None


class SH(Entry):
    def __init__(self):
        super().__init__(self)


class PH(Entry):
    pass



if __name__ == '__main__':
    pys = pystream('./hello')
    pys.set_endianness(1)
    pys.set_bitness(2)
    elf_header = EH()
    elf_header.read(pys)
