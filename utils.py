def hex_to_dec(bytearr):
    val = 0
    for byte in bytearr:
        val *= 2**8
        val += byte

    return val
