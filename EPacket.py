from ctypes.wintypes import PRECTL
from functools import reduce
import inspect
from SnifferConstants import *
from Utils import *

class Base:
    def __init__(self, data: str) -> None:
        self.__bytes = data
        self.__bits = reduce(
            lambda a, b: a + b, 
            list(map(
                lambda x: bin(int(x, HEX_SCALE))[2:].zfill(BITS_PER_HEX), 
                list(chunks(data, BYTE_HEX_LEN))
            ))
        )
    def _getField(self, field: str, wrapper_class, result_class = str) -> str:
        acu_len = 0
        len_multiplier = BYTE_HEX_LEN
        cur_data = self.__bytes
        for key, val in vars(wrapper_class).items():
            if key.isupper():
                name, value, *extra = val
                change_flag = extra[0] if extra else ''
                if change_flag == TURN_TO_BITS:
                    acu_len *= BITS_PER_HEX
                    len_multiplier = BIT_LEN
                    cur_data = self.__bits
                if change_flag == TURN_TO_BYTES:
                    acu_len //= BITS_PER_HEX
                    len_multiplier = BYTE_HEX_LEN
                    cur_data = self.__bytes
                if name == field:
                    l = int(acu_len * len_multiplier)
                    r = int(l + value * len_multiplier)
                    return result_class(cur_data[l : r])
                else:
                    acu_len += value
    def getSubBytes(self, l: int, r: int) -> str:
        return self.__bytes[l:r]
    def getSubBits(self, l: int, r: int) -> str:
        return self.__bits[l:r]
    def hexData(self, perChunk = BYTE_HEX_LEN, perLine = 12):
        return reduce(
            lambda a, b: a + ENDL + b,
            list(map(
                lambda a : reduce(lambda x, y: x + SPACE + y, a),
                list(chunks(
                    list(chunks(self.__bytes, perChunk)), 
                    perLine
                ))
            ))
        )
    def binData(self, perChunk = BITS_PER_HEX, perLine = 12):
        return reduce(
            lambda a, b: a + ENDL + b,
            list(map(
                lambda a : reduce(lambda x, y: x + SPACE + y, a),
                list(chunks(
                    list(chunks(self.__bits, perChunk)), 
                    perLine
                ))
            ))
        )

class EFrame(Base):
    DESTINATION_ADDRESS = ['DESTINATION_ADDRESS', 6]
    SOURCE_ADDRESS = ['SOURCE_ADDRESS', 6]
    TYPE = ['TYPE', 2]
    def __init__(self, data: str) -> None:
        Base.__init__(self, data)
    def getField(self, field: str, len: int = 0) -> str:
        return self._getField(field, EFrame)

class DS(Base):
    DSCP = ['DSCP', 6, TURN_TO_BITS]
    ECN = ['ECN', 2]
    def __init__(self, data: str) -> None:
        super().__init__(data)
    def getField(self, field: str, *args) -> str:
        return self._getField(field, DS)

class TOS(Base):
    PRECEDENCE = ['PRECEDENCE', 3, TURN_TO_BITS]
    TYPE_OF_SERVICE = ['TYPE_OF_SERVICE', 4]
    MBZ = ['MBZ', 1]
    def __init__(self, data: str) -> None:
        super().__init__(data)
    def getField(self, field: str, len: int, *args) -> str:
        return self._getField(field, TOS)

class TCP(Base):
    SOURCE_PORT = ['SOURCE_PORT', 2]
    DESTINATION_PORT = ['DESTINATION_PORT', 2]
    SEQUENCE_NUMBER = ['SEQUENCE_NUMBER', 4]
    ACK = ['ACK', 4]
    HEADER_LENGTH = ['HEADER_LENGTH', 4, TURN_TO_BITS]
    RESERVED = ['RESERVED', 3]
    FLAGS = ['FLAGS', 9]
    WINDOW_SZ = ['WINDOW_SZ', 2, TURN_TO_BYTES]
    CHECKSUM = ['CHECKSUM', 2]
    URGENT_POINT = ['URGENT_POINT', 2]
    def __init__(self, data: str) -> None:
        super().__init__(data)
    def getField(self, field: str, len: int, *args) -> str:
        class_def = str
        if args and inspect.isclass(args[0]):
            class_def = args[0]
        return self._getField(field, TCP, class_def)

class IPDataPacket(Base):
    VERSION = ['VERSION', 0.5]
    IHL = ['IHL', 0.5]
    # DS = ['DS', 1, DS]
    TOS = ['TOS', 1, TOS]
    TOTAL_LENGTH = ['TOTAL_LENGTH', 2]
    IDENTIFICATION = ['IDENTIFICATION', 2]
    FLAGS = ['FLAGS', 3, TURN_TO_BITS]
    OFFSET = ['OFFSET', 13]
    TTL = ['TTL', 1, TURN_TO_BYTES]
    PROTOCOL = ['PROTOCOL', 1]
    CHECKSUM = ['CHECKSUM', 2]
    SOURCE_ADDRESS = ['SOURCE_ADDRESS', 4]
    DESTINATION_ADDRESSS = ['DESTINATION_ADDRESSS', 4]
    def __init__(self, data: str) -> None:
        Base.__init__(self, data)
    def getField(self, field: str, len: int, *args) -> str:
        class_def = str
        if args and inspect.isclass(args[0]):
            class_def = args[0]
        return self._getField(field, IPDataPacket, class_def)
    def __sumBin16len(self, x: str, y: str) -> str:
        sum = bin(int(x, BIN_SCALE) + int(y, BIN_SCALE))[2:][::-1]
        foo = list(map(lambda a : a[::-1],list(chunks(sum, 16))))
        return foo[0] if len(foo) == 1 else self.__sumBin16len(foo[0], foo[1])

    def verifyChecksum(self) -> str:
        version = int(self.getField(*IPDataPacket.VERSION))
        header_len = version * int(self.getField(*IPDataPacket.IHL))
        data = self.binData(version // BYTE_HEX_LEN * BITS_PER_HEX, header_len * BITS_PER_HEX)
        foo = reduce(
            self.__sumBin16len,
            list(data.split(SPACE))
        )
        return hex(int(foo, BIN_SCALE))

class EPacket(Base):
    ETHERNET_FRAME = ['ETHERNET_FRAME', 14, EFrame]
    IP_DATA_PACKET = ['IP_FRAME', 20, IPDataPacket]
    TCP = ['TCP', 20, TCP]
    def __init__(self, packet: str) -> None:
        Base.__init__(self, packet)
    def getField(self, field: str, len: int, class_def):
        return self._getField(field, EPacket, class_def)
    