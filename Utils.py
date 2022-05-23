from SnifferConstants import BYTE_HEX_LEN, HEX_SCALE


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