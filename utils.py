from typedef import *

def hex_to_val(bytearr,c_type): # bytearr is an endian-less byte array

    val, is_negative = 0, False
    for idx, byte in enumerate(bytearr):
        # check if signed
        if not idx and byte // 127 and c_type < 0:
            is_negative = True

        val *= 2**8
        if not is_negative:
            val += byte
        else:
            val -= (255 - byte)

    return val if not is_negative else val-1



if __name__ == '__main__':
    assert hex_to_val(b'\xff',uchar) == 255
    assert hex_to_val(b'\xff',char) == -1

    assert hex_to_val(b'\xff\xff',uint16_t) == 65535
    assert hex_to_val(b'\xff\xff',int16_t) == -1

    assert hex_to_val(b'\x87\x65\x43\x21',uint32_t) == 2271560481
    assert hex_to_val(b'\x87\x65\x43\x21',int32_t) == -2023406815

