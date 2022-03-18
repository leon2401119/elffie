class SectionHeader:
    def __init__(self):
        self.name = None
        self.type = None
        self.flags = None
        self.vaddr = None
        self.file_offset = None
        self.size = None
        self.link = None
        self.info = None
        self.align = None
        self.entry_size = None

    def is_executable(self):
        return self.flags & 0x4 if self.flags else False


class Sections:
    def __init__(self):
        self.__sections_list = []
        self.__sections_dict = {}
        self.__sections_name = []

    def add_section(self,name,section):
        self.__sections_list.append(section)
        self.__sections_dict[name] = section
        self.__sections_name.append(name)

    def __getitem__(self,key):
        if type(key) is int:
            return self.__sections_list[key]
        elif type(key) is str:
            return self.__sections_dict[key]

    def __len__(self):
        return len(self.__Sections_list)

    def __iter__(self):
        self.__counter = 0
        return self

    def __next__(self):
        if self.__counter < len(self.__sections_list):
            section = self.__sections_list[self.__counter]
            self.__counter += 1
            return section
        else:
            raise StopIteration

    def keys(self):
        return self.__sections_name
