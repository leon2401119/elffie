from ioctl import pystream

class ELF:

    ''' define static class members '''
    self.BITNESS_DICT = {
	1 : '32-bit',
	2 : '64-bit'
    }
    self.ENDIANNESS_DICT = {
	1 : 'Little Endian',
	2 : 'Big Endian'
    }
    self.ABI_DICT = {}
    self.ISA_DICT = {}
    self.TYPE_DICT = {}

    def __init__(self,filepath):
	# set up the pystream object and initiate reading for different parts
	self.__pys = pystream(filepath)
        self.__read_eh()
        

    def __getitem__(self,section_name):
	# get raw section content
	try:
	    section = self.sections[section_name]
	except Keyerror:
	    print(f'Cannot find section {section_name}')
	    return None
	return section

    def __setitem(self,section_name,section_content):
        # TODO : add a section (future)
	raise NotImplementedError()

    def __read_eh(self) -> None:
        self.__pys.seek(0)
	self.header = ElfHeader()
        self.header.__prep(self.__pys)
	
    def __read_shs(self):
	self.sections = Sections()
	for ...
	    sh = self.__read_sh()
	    shname = ...
	    self.section[shname] = sh
			
    def __read_sh(self):
	section = Section()
	...
	return sh 	
		

    def magic(self) -> bytes:
	pass
    def bitness(self) -> str:
	return self.BITNESS_DICT[self.header[E.IDENT][EI.CLASS]]
    def endianess(self) -> str:
	return self.ENDIANNESS_DICT[self.header[E.IDENT][EI.DATA]]
    def abi(self) -> str:
	return somedict[self.header[E.OSABI]]
    def isa(self) -> str:
	return somedict[self.header[E.MACHINE]]
    def entry(self) -> str:
	return self.header[EI.ENTRY].hex()
    def type(self) -> str:
	return self.TYPE_DCT[self.header[E.TYPE]]

    def is_32bit(self) -> bool:
		return self.header[E.IDENT][EI.CLASS] == 1
    def is_64bit(self) -> bool:
		return self.header[E.IDENT][EI.CLASS] == 2
