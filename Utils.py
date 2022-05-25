from SnifferConstants import BYTE_HEX_LEN, HEX_SCALE, SPACE, NO_CHAR, BIN_SCALE


from functools import reduce

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def hexToIP(s):
    return reduce(
            lambda x, y: x + '.' + y,
            list(map(lambda x: str(int(x, HEX_SCALE)), list(chunks(s, BYTE_HEX_LEN))))
        )
def hexToMAC(s):
    return reduce(lambda x, y: str(x) + ':' + str(y), list(chunks(s, BYTE_HEX_LEN)))

def addHex(a, b):
    a = str(bin(int(a, HEX_SCALE))[2:].zfill(16))
    b = str(bin(int(b, HEX_SCALE))[2:].zfill(16))
    return str(hex(int(sumBin16len(a, b), BIN_SCALE)))[2:].zfill(4)

def subHex(a, b):
    return str(hex(int(a, HEX_SCALE) - int(b, HEX_SCALE)))[2:].zfill(4)

def addListHex(a):
    if not a:
        return "0000"
    return reduce(addHex, list(chunks((' '.join(a.splitlines())).replace(SPACE, NO_CHAR), 4)))

def sumBin16len(x: str, y: str) -> str:
        sum = bin(int(x, BIN_SCALE) + int(y, BIN_SCALE))[2:][::-1]
        foo = list(map(lambda a : a[::-1],list(chunks(sum, 16))))
        return foo[0] if len(foo) == 1 else sumBin16len(foo[0], foo[1])

def decimal(s):
    return '0d' + str(s)

def hexadecimal(s):
    return '0x' + str(s).upper()

def binary(s):
    return '0b' + str(s)