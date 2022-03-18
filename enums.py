from enum import Enum

class ET(Enum):
    ET_NONE = 0x00,
    ET_REL = 0x01,
    ET_EXEC = 0x02,
    ET_DYN = 0x03,
    ET_CORE = 0x04


class SHT(Enum):
    SHT_NULL = 0x0,
    SHT_PROGBITS = 0x1,


