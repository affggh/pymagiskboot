from ctypes import (
    Union,
    Structure,
    Array,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
    c_char,
    c_char_p,
    c_int,
    c_int16,
    c_int32,
    c_int64,
    c_bool,
    c_float,
    c_double,
    c_long,
    c_longlong,
    c_ulonglong,

    memset,
    memmove
)
from io import BytesIO
import mmap
from enum import Enum, auto
from .format import Format, check_fmt
from io import (
    IOBase,
    SEEK_CUR, 
    SEEK_END, 
    SEEK_SET
)
from .magiskboot import *


class MtkHdr(Structure):
    _fields_ = [
        ("magic", c_uint32),
        ("size", c_uint32),
        ("name", c_char * 32),
        ("padding", c_char * 472)
    ]
    _pack_ = 1

class DhtbHdr(Structure):
    _fields_ = [
        ("magic", c_char * 8),  # char[8]
        ("checksum", c_uint8 * 40),  # uint8_t[40]
        ("size", c_uint32),  # uint32_t
        ("padding", c_char * 460)  # char[460]
    ]
    _pack_ = 1

class BlobHdr(Structure):
    _fields_ = [
        ("secure_magic", c_char * 20),  # char[20]
        ("datalen", c_uint32),  # uint32_t
        ("signature", c_uint32),  # uint32_t
        ("magic", c_char * 16),  # char[16]
        ("hdr_version", c_uint32),  # uint32_t
        ("hdr_size", c_uint32),  # uint32_t
        ("part_offset", c_uint32),  # uint32_t
        ("num_parts", c_uint32),  # uint32_t
        ("unknown", c_uint32 * 7),  # uint32_t[7]
        ("name", c_char * 4),  # char[4]
        ("offset", c_uint32),  # uint32_t
        ("size", c_uint32),  # uint32_t
        ("version", c_uint32)  # uint32_t
    ]
    _pack_ = 1

class ZimageHdr(Structure):
    _fields_ = [
        ("code", c_uint32 * 9),  # uint32_t[9]
        ("magic", c_uint32),  # uint32_t
        ("start", c_uint32),  # uint32_t
        ("end", c_uint32),  # uint32_t
        ("endian", c_uint32)  # uint32_t
    ]
    _pack_ = 1

AVB_FOOTER_MAGIC_LEN = 4
AVB_MAGIC_LEN = 4
AVB_RELEASE_STRING_SIZE = 48

class AvbFooter(Structure):
    _fields_ = [
        ("magic", c_uint8 * AVB_FOOTER_MAGIC_LEN),  # uint8_t[4]
        ("version_major", c_uint32),  # uint32_t
        ("version_minor", c_uint32),  # uint32_t
        ("original_image_size", c_uint64),  # uint64_t
        ("vbmeta_offset", c_uint64),  # uint64_t
        ("vbmeta_size", c_uint64),  # uint64_t
        ("reserved", c_uint8 * 28)  # uint8_t[28]
    ]
    _pack_ = 1

class AvbVBMetaImageHeader(Structure):
    _fields_ = [
        ("magic", c_uint8 * AVB_MAGIC_LEN),  # uint8_t[4]
        ("required_libavb_version_major", c_uint32),  # uint32_t
        ("required_libavb_version_minor", c_uint32),  # uint32_t
        ("authentication_data_block_size", c_uint64),  # uint64_t
        ("auxiliary_data_block_size", c_uint64),  # uint64_t
        ("algorithm_type", c_uint32),  # uint32_t
        ("hash_offset", c_uint64),  # uint64_t
        ("hash_size", c_uint64),  # uint64_t
        ("signature_offset", c_uint64),  # uint64_t
        ("signature_size", c_uint64),  # uint64_t
        ("public_key_offset", c_uint64),  # uint64_t
        ("public_key_size", c_uint64),  # uint64_t
        ("public_key_metadata_offset", c_uint64),  # uint64_t
        ("public_key_metadata_size", c_uint64),  # uint64_t
        ("descriptors_offset", c_uint64),  # uint64_t
        ("descriptors_size", c_uint64),  # uint64_t
        ("rollback_index", c_uint64),  # uint64_t
        ("flags", c_uint32),  # uint32_t
        ("rollback_index_location", c_uint32),  # uint32_t
        ("release_string", c_uint8 * AVB_RELEASE_STRING_SIZE),  # uint8_t[48]
        ("reserved", c_uint8 * 80)  # uint8_t[80]
    ]
    _pack_ = 1

BOOT_MAGIC_SIZE = 8
BOOT_NAME_SIZE = 16
BOOT_ID_SIZE = 32
BOOT_ARGS_SIZE = 512
BOOT_EXTRA_ARGS_SIZE = 1024
VENDOR_BOOT_ARGS_SIZE = 2048
VENDOR_RAMDISK_NAME_SIZE = 32
VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE = 16

class BootImgHdrV0Common(Structure):
    _fields_ = [
        ("magic", c_char * BOOT_MAGIC_SIZE),  # char[8]
        ("kernel_size", c_uint32),  # uint32_t
        ("kernel_addr", c_uint32),  # uint32_t
        ("ramdisk_size", c_uint32),  # uint32_t
        ("ramdisk_addr", c_uint32),  # uint32_t
        ("second_size", c_uint32),  # uint32_t
        ("second_addr", c_uint32)  # uint32_t
    ]
    _pack_ = 1

class BootImgHdrV0U1(Union):
    _fields_ = [
        ("unknown", c_uint32),
        ("page_size", c_uint32)
    ]

class BootImgHdrV0U2(Union):
    _fields_ = [
        ("header_version", c_uint32),
        ("extra_size", c_uint32)
    ]

class BootImgHdrV0(Structure):
    _fields_ = [
        ("base", BootImgHdrV0Common),
        ("tags_addr", c_uint32),
        ("u1", BootImgHdrV0U1),
        ("u2", BootImgHdrV0U2),
        ("os_version", c_uint32),
        ("name", c_char * BOOT_NAME_SIZE),
        ("cmdline", c_char *BOOT_ARGS_SIZE),
        ("id", c_char * BOOT_ID_SIZE),
        ("extra_cmdline", c_char* BOOT_EXTRA_ARGS_SIZE)
    ]
    _pack_ = 1

class BootImgHdrV1(Structure):
    _fields_ = [
        ("v0", BootImgHdrV0),
        ("recovery_dtbo_size", c_uint32),
        ("recovery_debo_offset", c_uint64),
        ("header_size", c_uint32)
    ]
    _pack_ = 1

class BootImgHdrV2(Structure):
    _fields_ = [
        ("v1", BootImgHdrV1),
        ("dtb_size", c_uint32),
        ("dtb_addr", c_uint64)
    ]
    _pack_ = 1

class BootImgHdrPxa(Structure):
    _fields_ = [
        ("base", BootImgHdrV0Common),
        ("extra_size", c_uint32),
        ("unknown", c_uint32),
        ("tags_addr", c_uint32),
        ("page_size", c_uint32),
        ("name", c_char * 4),
        ("cmdline", c_char * BOOT_ARGS_SIZE),
        ("id", c_char * BOOT_ID_SIZE),
        ("extra_cmdline", c_char * BOOT_EXTRA_ARGS_SIZE)
    ]
    _pack_ = 1

class BootImgHdrV3(Structure):
    _fields_ = [
        ("magic", c_uint8 * BOOT_MAGIC_SIZE),
        ("kernel_size", c_uint32),
        ("ramdisk_size", c_uint32),
        ("os_version", c_uint32),
        ("header_size", c_uint32),
        ("reserved", c_uint32 * 4),
        ("header_version", c_uint32),
        ("cmdline", c_char * (BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE))
    ]
    _pack_ = 1

class BootImgHdrVndV3(Structure):
    _fields_ = [
        ("magic", c_uint8 * BOOT_MAGIC_SIZE),
        ("header_version", c_uint32),
        ("page_size", c_uint32),
        ("kernel_addr", c_uint32),
        ("ramdisk_addr", c_uint32),
        ("ramdisk_size", c_uint32),
        ("cmdline", c_char * VENDOR_BOOT_ARGS_SIZE),
        ("tags_addr", c_uint32),
        ("name", c_char * BOOT_NAME_SIZE),
        ("header_size", c_uint32),
        ("dtb_size", c_uint32),
        ("dtb_addr", c_uint64)
    ]
    _pack_ = 1

class BootImgHdrV4(Structure):
    _fields_ = [
        ("v3", BootImgHdrV3),
        ("signature_size", c_uint32)
    ]
    _pack_ = 1

class BootImgHdrVndV4(Structure):
    _fields_ = [
        ("v3", BootImgHdrVndV3),
        ("vendor_ramdisk_table_size", c_uint32),
        ("vendor_ramdisk_table_entry_num", c_uint32),
        ("vendor_ramdisk_table_entry_size", c_uint32),
        ("bootconfig_size", c_uint32)
    ]
    _pack_ = 1

class VendorRamdiskTableEntryV4(Structure):
    _fields_ = [
        ("ramdisk_size", c_uint32),
        ("ramdisk_offset", c_uint32),
        ("ramdisk_type", c_uint32),
        ("ramdisk_name", c_uint8 * VENDOR_RAMDISK_NAME_SIZE),
        ("board_id", c_uint32 * VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE)
    ]
    _pack_ = 1

PADDING = 15

class DynImgHdr:
    def __init__(self, is_vendor: bool):
        self.is_vendor = c_bool(is_vendor)
        self.kernel_size = c_uint32()
        self.ramdisk_size = c_uint32()
        self.second_size = c_uint32()
        self.page_size = c_uint32(0)
        self.header_version = c_uint32(0)
        self.extra_size = c_uint32()
        self.os_version = c_uint32()
        self.name = c_char_p(None)
        self.cmdline = c_char_p(None)
        self.id = c_char_p(None)
        self.extra_cmdline = c_char_p(None)
        self.kernel_dt_size = c_uint32(0)
        self.recovery_dtbo_size = c_uint32()
        self.recovery_dtbo_offset = c_uint64()
        self.header_size = c_uint32()
        self.dtb_size = c_uint32()
        self.signature_size = c_uint32(0)
        self.vendor_ramdisk_table_size = c_uint32(0)
        self.bootconfig_size = c_uint32(0)

        self.v2_hdr = BootImgHdrV2()
        self.v4_hdr = BootImgHdrV4()
        self.v4_vnd = BootImgHdrVndV4()
        self.raw = None

    def hdr_size(self):
        # 根据需要实现此方法
        pass

    def hdr_space(self):
        return self.page_size.value

    def clone(self):
        # 根据需要实现此方法
        pass

    def raw_hdr(self):
        return self.raw

    def print(self):
        ver = self.header_version.value
        print("%-*s [%u]" %(PADDING, "HEADER_VER", ver))
        if not self.is_vendor.value:
            print("%-*s [%u]" %(PADDING, "KERNEL_SZ", self.kernel_size.value))
        if ver < 3:
            print("%-*s [%u]" %(PADDING, "SECOND_SZ", self.second_size.value))
        if ver == 0:
            print("%-*s [%u]" %(PADDING, "EXTRA_SZ", self.extra_size.value))
        if ver ==  1 or ver ==2:
            print("%-*s [%u]" %(PADDING, "RECOV_DTBO_SZ", self.recovery_dtbo_size.value))
        if ver == 2 or self.is_vendor.value:
            print("%-*s [%u]" %(PADDING, "DTB_SZ", self.dtb_size.value))
        
        os_ver = self.os_version.value
        if (os_ver):
            a,b,c,y,m = [0] * 5
            version = os_ver >> 11
            patch_level = os_ver & 0x7ff

            a = (version >> 14) & 0x7f
            b = (version >> 7) & 0x7f
            c = version & 0x7f
            print("%-s [%d.%d.%d]" %(PADDING, "OS_VERSION", a, b, c))

            y = (patch_level >> 4) + 2000
            m = patch_level & 0xf
            print("%-*s [%d-%02d]" %(PADDING, "OS_PATCH_LEVEL", y, m))

        print("%-*s [%u]" %(PADDING, "PAGESIZE", self.page_size.value))
        n = self.name.value
        if n:
            print("%-*s [%s]" %(PADDING, "NAME", n))
        
        print("%-*s [%.*s%.*s]" %(PADDING, "CMDLINE", BOOT_ARGS_SIZE, self.cmdline.value, BOOT_EXTRA_ARGS_SIZE, self.extra_cmdline.value))
        checksum = self.id.value
        if checksum:
            print("%-*s [" %(PADDING, "CHECKSUM"), end='')
            for i in range(16):
                print("%02x" %(checksum[i]), end='')
            print("]")

    def dump_hdr_file(self):
        with open(HEADER_FILE, 'w') as fp:
            if self.name.value:
                print("name=%s" %self.name.value, file=fp)
            print("cmdline=%.*s%.*s" %(BOOT_ARGS_SIZE, self.cmdline.value, BOOT_EXTRA_ARGS_SIZE, self.extra_cmdline.value), file=fp)
            ver = self.os_version.value
            if ver:
                version = ver >> 11
                patch_level = ver & 0x7ff

                a = (version >> 14) & 0x7f
                b = (version >> 7) & 0x7f
                c = version &0x7f
                print("os_version=%d.%d.%d" %(a, b, c), file=fp)

                y = (patch_level >> 4) + 2000
                m = patch_level & 0xf
                print("os_patch_level=%d-%02d" %(y, m), file=fp)

    def load_hdr_file(self):
        with open(HEADER_FILE, 'r') as fp:
            for line in iter(fp.readline, ""):
                buf = line.rstrip("\n").split("=")
                if buf.__len__() == 2:
                    key, value = buf[0], buf[1]
                    if key == "name" and self.name.value:
                        memset(self.name, 0, 16)
                        memmove(self.name, c_char_p(value.encode()), 15 if value.__len__() > 15 else value.__len__())
                    elif key == "cmdline":
                        memset(self.cmdline, 0, BOOT_ARGS_SIZE)
                        memset(self.extra_cmdline, 0, BOOT_EXTRA_ARGS_SIZE)
                        if value.__len__() > BOOT_ARGS_SIZE:
                            memmove(self.cmdline,c_char_p(value.encode()), BOOT_ARGS_SIZE)
                            len = min(value.__len__() - BOOT_ARGS_SIZE, BOOT_EXTRA_ARGS_SIZE)
                            memmove(self.extra_cmdline, c_char_p(bytes(value[BOOT_ARGS_SIZE:])), len)
                        else:
                            memmove(self.cmdline, c_char_p(value.encode()), value.__len__())
                    elif key == "os_version":
                        patch_level = self.os_version.value & 0x7ff
                        buf = [int(i) for i in value.split(".")]
                        a, b, c = buf[0], buf[1], buf[2]
                        self.os_version.value = (((a << 14) | (b << 7) | c) << 11) | patch_level
                    elif key == "os_patch_level":
                        os_ver = self.os_version.value >> 11
                        buf = [int(i) for i in value.split("-")]
                        y, m = buf[0], buf[1]
                        y -= 2000
                        self.os_version.value = (os_ver << 11) | (y << 4) | m

    @staticmethod
    def j32():
        return 0

    @staticmethod
    def j64():
        return 0

class DynImgHdrBoot(DynImgHdr):
    def __init__(self):
        super().__init__(False)

class DynImgCommon(DynImgHdrBoot):
    def __init__(self):
        super().__init__()

    def kernel_size(self):
        return self.v2_hdr.v1.v0.base.kernel_size

    def ramdisk_size(self):
        return self.v2_hdr.v1.v0.base.ramdisk_size

    def second_size(self):
        return self.v2_hdr.v1.v0.base.second_size

class DynImgV0(DynImgCommon):
    def __init__(self):
        super().__init__()
        self.v0_hdr = BootImgHdrV0()

    def page_size(self):
        return self.v0_hdr.u1.page_size

    def extra_size(self):
        return self.v0_hdr.u2.extra_size

    def os_version(self):
        return self.v0_hdr.os_version

    def name(self):
        return self.v0_hdr.name

    def cmdline(self):
        return self.v0_hdr.cmdline

    def id(self):
        return self.v0_hdr.id

    def extra_cmdline(self):
        return self.v0_hdr.extra_cmdline

class DynImgV1(DynImgV0):
    def __init__(self):
        super().__init__()
        self.v1_hdr = BootImgHdrV1()

    def header_version(self):
        return self.v1_hdr.v0.u2.header_version

    def recovery_dtbo_size(self):
        return self.v1_hdr.recovery_dtbo_size

    def recovery_dtbo_offset(self):
        return self.v1_hdr.recovery_dtbo_offset

    def header_size(self):
        return self.v1_hdr.header_size

    def extra_size(self):
        return self.j32()

class DynImgV2(DynImgV1):
    def __init__(self):
        super().__init__()
        self.v2_hdr = BootImgHdrV2()

    def dtb_size(self):
        return self.v2_hdr.dtb_size

class DynImgPxa(DynImgCommon):
    def __init__(self):
        super().__init__()
        self.hdr_pxa = BootImgHdrPxa()

    def extra_size(self):
        return self.hdr_pxa.extra_size

    def page_size(self):
        return self.hdr_pxa.page_size

    def name(self):
        return self.hdr_pxa.name

    def cmdline(self):
        return self.hdr_pxa.cmdline

    def id(self):
        return self.hdr_pxa.id

    def extra_cmdline(self):
        return self.hdr_pxa.extra_cmdline

class DynImgV3(DynImgHdrBoot):
    def __init__(self):
        super().__init__()
        self.v4_hdr = BootImgHdrV4()

    def kernel_size(self):
        return self.v4_hdr.v3.kernel_size

    def ramdisk_size(self):
        return self.v4_hdr.v3.ramdisk_size

    def os_version(self):
        return self.v4_hdr.v3.os_version

    def header_size(self):
        return self.v4_hdr.v3.header_size

    def header_version(self):
        return self.v4_hdr.v3.header_version

    def cmdline(self):
        return self.v4_hdr.v3.cmdline

    def page_size(self):
        return 4096

    def extra_cmdline(self):
        return self.v4_hdr.cmdline[BOOT_ARGS_SIZE:]

class DynImgV4(DynImgV3):
    def __init__(self,):
        super().__init__()
        self.v4_hdr = BootImgHdrV4()

    def signature_size(self):
        return self.v4_hdr.signature_size

class DynImgHdrVendor(DynImgHdr):
    def __init__(self):
        super().__init__(True)

    def is_vendor(self):
        return True

class BootFlag(Enum):
    MTK_KERNEL = auto()
    MTK_RAMDISK = auto()
    CHROMEOS_FLAG = auto()
    DHTB_FLAG = auto()
    SEANDROID_FLAG = auto()
    LG_BUMP_FLAG = auto()
    SHA256_FLAG = auto()
    BLOB_FLAG = auto()
    NOOKHD_FLAG = auto()
    ACCLAIM_FLAG = auto()
    AMONET_FLAG =  auto()
    AVB1_SIGNED_FLAG =  auto()
    AVB_FLAG =  auto()
    ZIMAGE_KERNEL =  auto()
    BOOT_FLAGS_MAX =  auto()

class BootImage:
    def __init__(self, image_path):
        print("Parsing image [%s]" %image_path)
        with open(image_path, 'rb') as image_file:
            self.map = mmap.mmap(image_file.fileno(), 0)
            fmt: Format = check_fmt(self.map, self.map.size())
        self.hdr = DynImgHdr(False)
        self.flags = [False] * BootFlag.BOOT_FLAGS_MAX.value
        self.k_fmt = Format.UNKNOWN
        self.r_fmt = Format.UNKNOWN
        self.e_fmt = Format.UNKNOWN
        self.payload: BytesIO
        self.tail: BytesIO
        self.k_hdr = MtkHdr()
        self.r_hdr = MtkHdr()
        self.z_hdr = ZimageHdr()
        self.z_info = {"hdr_sz": 0, "tail": None}
        self.avb_footer = AvbFooter()
        self.vbmeta = AvbVBMetaImageHeader()
        self.kernel = None
        self.ramdisk = None
        self.second = None
        self.extra = None
        self.recovery_dtbo = None
        self.dtb = None
        self.kernel_dtb: BytesIO
        self.ignore: BytesIO

    def __del__(self):
        del self.hdr
        self.map.close()

    def parse_image(self, addr, type):
        # Implement image parsing logic here
        pass

    def create_hdr(self, addr, type):
        # Implement header creation logic here
        pass

    def verify(self, cert=None):
        # Implement verification logic here
        pass

def decompress(format: Format, fd, i, size):
    pass

def compress(format: Format, fd, i, size):
    pass

def dump(buf: bytes, size: int, filename: str):
    if size == 0:
        return
    with open(filename, 'wb') as fd:
        fd.write(buf[:size])
    return

def xsendfile(fd: IOBase, ifd: IOBase, offset: int, size: int):
    chunk = 4096
    ifd.seek(SEEK_SET, offset)
    for i in range(0, size, chunk):
        fd.write(ifd.read(i))

def restore(fd: IOBase, filename: str):
    with open(filename, 'rb') as ifd:
        size = ifd.seek(0, SEEK_END)
        ifd.seek(0, SEEK_SET)
        xsendfile(fd, ifd, 0, size)
    return size

