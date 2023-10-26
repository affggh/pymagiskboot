from enum import Enum , auto
from mmap import mmap

class Format(Enum):
    UNKNOWN = auto()
    CHROMEOS = auto()
    AOSP = auto()
    AOSP_VENDOR = auto()
    DHTB = auto()
    BLOB = auto()
    GZIP = auto()
    ZOPFLI = auto()
    XZ = auto()
    LZMA = auto()
    BZIP2 = auto()
    LZ4 = auto()
    LZ4_LEGACY = auto()
    LZ4_LG = auto()
    LZOP = auto()
    MTK = auto()
    DTB = auto()
    ZIMAGE = auto()

# 魔数定义
BOOT_MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"
CHROMEOS_MAGIC = b"CHROMEOS"
GZIP1_MAGIC = b"\x1f\x8b"
GZIP2_MAGIC = b"\x1f\x9e"
LZOP_MAGIC = b"\x89LZO"
XZ_MAGIC = b"\xfd7zXZ"
BZIP_MAGIC = b"BZh"
LZ4_LEG_MAGIC = b"\x02\x21\x4c\x18"
LZ41_MAGIC = b"\x03\x21\x4c\x18"
LZ42_MAGIC = b"\x04\x22\x4d\x18"
MTK_MAGIC = b"\x88\x16\x88\x58"
DTB_MAGIC = b"\xd0\x0d\xfe\xed"
LG_BUMP_MAGIC = b"\x41\xa9\xe4\x67\x74\x4d\x1d\x1b\xa4\x29\xf2\xec\xea\x65\x52\x79"
DHTB_MAGIC = b"DHTB\x01\x00\x00\x00"
SEANDROID_MAGIC = b"SEANDROIDENFORCE"
TEGRABLOB_MAGIC = b"-SIGNED-BY-SIGNBLOB-"
NOOKHD_RL_MAGIC = b"Red Loader"
NOOKHD_GL_MAGIC = b"Green Loader"
NOOKHD_GR_MAGIC = b"Green Recovery"
NOOKHD_EB_MAGIC = b"eMMC boot.img+secondloader"
NOOKHD_ER_MAGIC = b"eMMC recovery.img+secondloader"
ACCLAIM_MAGIC = b"BauwksBoot"
AMONET_MICROLOADER_MAGIC = b"microloader"
AVB_FOOTER_MAGIC = b"AVBf"
AVB_MAGIC = b"AVB0"
ZIMAGE_MAGIC = b"\x18\x28\x6f\x01"

# 辅助宏定义
def COMPRESSED(fmt):
    return fmt >= Format.GZIP and fmt < Format.LZOP

def COMPRESSED_ANY(fmt):
    return fmt >= Format.GZIP and fmt <= Format.LZOP

def BUFFER_MATCH(buf, s):
    return buf.startswith(s)

def BUFFER_CONTAIN(buf, s):
    return s in buf

def check_fmt(buf, size: int):
    def CHECKED_MATCH(s):
        return (size >= (len(s)) and BUFFER_MATCH(buf, s))
    def memcmp(buf, buf2, length):
        return buf[:length] == buf2[:length]

    if (CHECKED_MATCH(CHROMEOS_MAGIC)):
        return Format.CHROMEOS
    elif (CHECKED_MATCH(BOOT_MAGIC)):
        return Format.AOSP
    elif (CHECKED_MATCH(VENDOR_BOOT_MAGIC)):
        return Format.AOSP_VENDOR
    elif (CHECKED_MATCH(GZIP1_MAGIC) or CHECKED_MATCH(GZIP2_MAGIC)):
        return Format.GZIP
    elif (CHECKED_MATCH(LZOP_MAGIC)):
        return Format.LZOP
    elif (CHECKED_MATCH(XZ_MAGIC)):
        return Format.XZ
    elif (size >= 13 and memcmp(buf, b"\x5d\x00\x00", 3) == 0
            and (buf[12] == '\xff' or buf[12] == '\x00')):
        return Format.LZMA
    elif (CHECKED_MATCH(BZIP_MAGIC)):
        return Format.BZIP2
    elif (CHECKED_MATCH(LZ41_MAGIC) or CHECKED_MATCH(LZ42_MAGIC)):
        return Format.LZ4
    elif (CHECKED_MATCH(LZ4_LEG_MAGIC)):
        return Format.LZ4_LEGACY
    elif (CHECKED_MATCH(MTK_MAGIC)):
        return Format.MTK
    elif (CHECKED_MATCH(DTB_MAGIC)):
        return Format.DTB
    elif (CHECKED_MATCH(DHTB_MAGIC)):
        return Format.DHTB
    elif (CHECKED_MATCH(TEGRABLOB_MAGIC)):
        return Format.BLOB_FMT
    elif (size >= 0x28 and memcmp(buf[0x24:], ZIMAGE_MAGIC, 4) == 0):
        return Format.ZIMAGE
    else:
        return Format.UNKNOWN

def Fmt2Name(fmt: Format):
    match fmt:
        case Format.GZIP:
            return "gzip"
        case Format.ZOPFLI:
            return "zopfli"
        case Format.LZOP:
            return "lzop"
        case Format.XZ:
            return "xz"
        case Format.LZMA:
            return "lzma"
        case Format.BZIP2:
            return "bzip2"
        case Format.LZ4:
            return "lz4"
        case Format.LZ4_LEGACY:
            return "lz4_legacy"
        case Format.LZ4_LG:
            return "lz4_lg"
        case Format.DTB:
            return "dtb"
        case Format.ZIMAGE:
            return "zimage"
        case _:
            return "raw"

def Fmt2Ext(fmt: Format):
    match fmt:
        case Format.GZIP | Format.ZOPFLI:
            return ".gz"
        case Format.LZOP:
            return ".lzo"
        case Format.XZ:
            return ".xz"
        case Format.LZMA:
            return ".lzma"
        case Format.BZIP2:
            return ".bz2"
        case Format.LZ4 | Format.LZ4_LEGACY | Format.LZ4_LG:
            return ".lz4"
        case _:
            return ""

def Name2Fmt(name: str):
    if False: pass
    elif name == "gzip": return Format.GZIP
    elif name == "zopfli": return Format.ZOPFLI
    elif name == "xz": return Format.XZ
    elif name == "lzma": return Format.LZMA
    elif name == "bzip2": return Format.BZIP2
    elif name == "lz4": return Format.LZ4
    elif name == "lz4_legacy": return Format.LZ4_LEGACY
    elif name == "lz4_lg": return Format.LZ4_LG
    else: return Format.UNKNOWN

# alias
fmt2name = Fmt2Name
fmt2ext = Fmt2Ext
name2fmt = Name2Fmt