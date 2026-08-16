import os
import struct


OUTPUT_DIR = "goodware"

# ==============================================================
# PE CONSTANTS
# ==============================================================

IMAGE_BASE = 0x00400000

PE_OFFSET = 0x80
HEADER_SIZE = 0x400

SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200

TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
DATA_RVA = 0x3000

TEXT_RAW = 0x400
RDATA_RAW = 0x600
DATA_RAW = 0x800

SECTION_RAW_SIZE = 0x200


# ==============================================================
# HELPER
# ==============================================================

def fixed_bytes(value, size):

    data = value.encode("ascii")

    if len(data) > size:
        raise ValueError(
            f"'{value}' is too long for {size} bytes"
        )

    return data + b"\x00" * (size - len(data))


# ==============================================================
# CREATE MOCK PE
# ==============================================================

def create_mock_pe(
    output_filename,
    dlls,
    imports,
    strings,
    sections=None
):

    if len(dlls) != 2:
        raise ValueError("Exactly 2 DLLs are required.")

    if len(imports) != 2:
        raise ValueError("Exactly 2 imports are required.")

    if sections is None:
        sections = [
            ".text",
            ".rdata",
            ".data"
        ]

    if len(sections) != 3:
        raise ValueError(
            "Exactly 3 sections are required."
        )

    # ==========================================================
    # DOS HEADER
    # ==========================================================

    dos_header = bytearray(0x40)

    dos_header[0:2] = b"MZ"

    struct.pack_into(
        "<I",
        dos_header,
        0x3C,
        PE_OFFSET
    )

    dos_stub = (
        b"\x0e\x1f\xba\x0e\x00"
        b"\xb4\x09\xcd\x21"
        b"\xb8\x01\x4c\xcd\x21"
        b"This program cannot be run in DOS mode.\r\r\n$"
    )

    dos_padding = b"\x00" * (
        PE_OFFSET
        - len(dos_header)
        - len(dos_stub)
    )

    # ==========================================================
    # PE SIGNATURE
    # ==========================================================

    pe_signature = b"PE\x00\x00"

    # ==========================================================
    # COFF FILE HEADER
    # ==========================================================

    file_header = struct.pack(
        "<HHIIIHH",

        0x014C,       # Machine: x86

        3,             # Number of sections

        0x65000000,   # Timestamp

        0,             # PointerToSymbolTable

        0,             # NumberOfSymbols

        224,           # SizeOfOptionalHeader

        0x0102         # Characteristics
    )

    # ==========================================================
    # PE32 OPTIONAL HEADER
    #
    # PE32 optional header = exactly 224 bytes:
    #
    # Standard fields = 96 bytes
    # Data directories = 128 bytes
    # ==========================================================

    optional_header = struct.pack(

        "<HBB"
        "9I"
        "6H"
        "4I"
        "2H"
        "6I",

        0x010B,        # Magic = PE32

        14,             # MajorLinkerVersion
        0,              # MinorLinkerVersion

        0x200,          # SizeOfCode

        0x400,          # SizeOfInitializedData

        0,              # SizeOfUninitializedData

        TEXT_RVA,       # AddressOfEntryPoint

        TEXT_RVA,       # BaseOfCode

        DATA_RVA,       # BaseOfData

        IMAGE_BASE,     # ImageBase

        SECTION_ALIGNMENT,

        FILE_ALIGNMENT,

        6,              # MajorOperatingSystemVersion
        0,              # MinorOperatingSystemVersion

        0,              # MajorImageVersion
        0,              # MinorImageVersion

        6,              # MajorSubsystemVersion
        0,              # MinorSubsystemVersion

        0,              # Win32VersionValue

        0x4000,         # SizeOfImage

        HEADER_SIZE,    # SizeOfHeaders

        0,              # CheckSum

        3,              # Subsystem = Windows Console

        0x8140,         # DllCharacteristics

        0x100000,       # SizeOfStackReserve
        0x1000,         # SizeOfStackCommit

        0x100000,       # SizeOfHeapReserve
        0x1000,         # SizeOfHeapCommit

        0,              # LoaderFlags

        16              # NumberOfRvaAndSizes
    )

    # ==========================================================
    # DATA DIRECTORIES
    # ==========================================================

    data_directories = bytearray(16 * 8)

    # Import Directory
    #
    # RVA 0x2000
    # Size = 40 bytes
    #
    # Two descriptors + null descriptor
    #

    struct.pack_into(
        "<II",
        data_directories,

        1 * 8,

        RDATA_RVA,
        40
    )

    # ==========================================================
    # SECTION HEADERS
    # ==========================================================

    sec_text = struct.pack(
        "<8sIIIIIIHHI",

        fixed_bytes(
            sections[0],
            8
        ),

        0x200,              # VirtualSize

        TEXT_RVA,           # VirtualAddress

        SECTION_RAW_SIZE,   # SizeOfRawData

        TEXT_RAW,           # PointerToRawData

        0,
        0,

        0,
        0,

        0x60000020          # CODE | EXECUTE | READ
    )

    sec_rdata = struct.pack(
        "<8sIIIIIIHHI",

        fixed_bytes(
            sections[1],
            8
        ),

        0x200,

        RDATA_RVA,

        SECTION_RAW_SIZE,

        RDATA_RAW,

        0,
        0,

        0,
        0,

        0x40000040          # INITIALIZED_DATA | READ
    )

    sec_data = struct.pack(
        "<8sIIIIIIHHI",

        fixed_bytes(
            sections[2],
            8
        ),

        0x200,

        DATA_RVA,

        SECTION_RAW_SIZE,

        DATA_RAW,

        0,
        0,

        0,
        0,

        0xC0000040          # READ | WRITE
    )

    # ==========================================================
    # BUILD HEADERS
    # ==========================================================

    headers = (
        dos_header
        + dos_stub
        + dos_padding
        + pe_signature
        + file_header
        + optional_header
        + data_directories
        + sec_text
        + sec_rdata
        + sec_data
    )

    if len(headers) > HEADER_SIZE:
        raise ValueError(
            f"Headers exceed {HEADER_SIZE:#x} bytes"
        )

    headers += b"\x00" * (
        HEADER_SIZE - len(headers)
    )

    # ==========================================================
    # .TEXT SECTION
    #
    # Deliberately harmless static content.
    # ==========================================================

    text_marker = (
        b"SYNTHETIC_GOODWARE_SAMPLE\x00"
    )

    text_data = (
        text_marker
        + b"\x90" * (
            SECTION_RAW_SIZE
            - len(text_marker)
        )
    )

    # ==========================================================
    # .RDATA SECTION
    #
    # Import table:
    #
    # 0x00  Descriptor 1
    # 0x14  Descriptor 2
    # 0x28  Null descriptor
    #
    # 0x3C  INT #1
    # 0x44  INT #2
    #
    # 0x4C  IAT #1
    # 0x54  IAT #2
    #
    # 0xA0  DLL #1
    # 0xB0  DLL #2
    #
    # 0xC0  Hint/Name #1
    # 0xD0  Hint/Name #2
    # ==========================================================

    rdata = bytearray(
        SECTION_RAW_SIZE
    )

    # ------------------------------
    # RVAs
    # ------------------------------

    int1_rva = RDATA_RVA + 0x3C
    int2_rva = RDATA_RVA + 0x44

    iat1_rva = RDATA_RVA + 0x4C
    iat2_rva = RDATA_RVA + 0x54

    dll1_rva = RDATA_RVA + 0xA0
    dll2_rva = RDATA_RVA + 0xB0

    name1_rva = RDATA_RVA + 0xC0
    name2_rva = RDATA_RVA + 0xD0

    # ------------------------------
    # Import Descriptor #1
    # ------------------------------

    struct.pack_into(
        "<IIIII",
        rdata,
        0x00,

        int1_rva,
        0,
        0,
        dll1_rva,
        iat1_rva
    )

    # ------------------------------
    # Import Descriptor #2
    # ------------------------------

    struct.pack_into(
        "<IIIII",
        rdata,
        0x14,

        int2_rva,
        0,
        0,
        dll2_rva,
        iat2_rva
    )

    # Descriptor #3 remains zero
    # -> Import table terminator

    # ------------------------------
    # INT #1
    # ------------------------------

    struct.pack_into(
        "<II",
        rdata,
        0x3C,

        name1_rva,
        0
    )

    # ------------------------------
    # INT #2
    # ------------------------------

    struct.pack_into(
        "<II",
        rdata,
        0x44,

        name2_rva,
        0
    )

    # ------------------------------
    # IAT #1
    # ------------------------------

    struct.pack_into(
        "<II",
        rdata,
        0x4C,

        name1_rva,
        0
    )

    # ------------------------------
    # IAT #2
    # ------------------------------

    struct.pack_into(
        "<II",
        rdata,
        0x54,

        name2_rva,
        0
    )

    # ------------------------------
    # DLL names
    # ------------------------------

    dll1 = (
        dlls[0].encode("ascii")
        + b"\x00"
    )

    dll2 = (
        dlls[1].encode("ascii")
        + b"\x00"
    )

    rdata[
        0xA0:
        0xA0 + len(dll1)
    ] = dll1

    rdata[
        0xB0:
        0xB0 + len(dll2)
    ] = dll2

    # ------------------------------
    # Import name #1
    # ------------------------------

    imp1 = (
        imports[0].encode("ascii")
        + b"\x00"
    )

    struct.pack_into(
        "<H",
        rdata,
        0xC0,
        0
    )

    rdata[
        0xC2:
        0xC2 + len(imp1)
    ] = imp1

    # ------------------------------
    # Import name #2
    # ------------------------------

    imp2 = (
        imports[1].encode("ascii")
        + b"\x00"
    )

    struct.pack_into(
        "<H",
        rdata,
        0xD0,
        0
    )

    rdata[
        0xD2:
        0xD2 + len(imp2)
    ] = imp2

    # ==========================================================
    # .DATA SECTION
    #
    # Printable strings
    # ==========================================================

    data_payload = b""

    for string in strings:

        data_payload += (
            string.encode(
                "ascii",
                errors="ignore"
            )
            + b"\x00"
        )

    if len(data_payload) > SECTION_RAW_SIZE:
        raise ValueError(
            "String data exceeds section size."
        )

    data_section = (
        data_payload
        + b"\x00" * (
            SECTION_RAW_SIZE
            - len(data_payload)
        )
    )

    # ==========================================================
    # FINAL PE
    # ==========================================================

    final_data = (
        headers
        + text_data
        + bytes(rdata)
        + data_section
    )

    with open(
        output_filename,
        "wb"
    ) as f:

        f.write(final_data)

    print(
        f"[+] Created {output_filename}"
    )


# ==============================================================
# GENERATE GOODWARE
# ==============================================================

def main():

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    samples = [

        {
            "dlls": [
                "KERNEL32.dll",
                "USER32.dll"
            ],

            "imports": [
                "CreateFileA",
                "MessageBoxA"
            ],

            "strings": [
                "Microsoft Windows",
                "Document Viewer",
                "Open Document",
                "Synthetic Goodware"
            ]
        },

        {
            "dlls": [
                "KERNEL32.dll",
                "USER32.dll"
            ],

            "imports": [
                "CreateFileA",
                "MessageBoxA"
            ],

            "strings": [
                "Microsoft Windows",
                "Image Viewer",
                "Open Image",
                "Synthetic Goodware"
            ]
        },

        {
            "dlls": [
                "KERNEL32.dll",
                "ADVAPI32.dll"
            ],

            "imports": [
                "RegOpenKeyA",
                "CloseHandle"
            ],

            "strings": [
                "Microsoft Windows",
                "System Utility",
                "Configuration",
                "Synthetic Goodware"
            ]
        },

        {
            "dlls": [
                "KERNEL32.dll",
                "USER32.dll"
            ],

            "imports": [
                "GetComputerNameA",
                "MessageBoxA"
            ],

            "strings": [
                "Microsoft Windows",
                "System Information",
                "Computer Information",
                "Synthetic Goodware"
            ]
        },

        {
            "dlls": [
                "KERNEL32.dll",
                "ADVAPI32.dll"
            ],

            "imports": [
                "RegOpenKeyA",
                "CreateFileA"
            ],

            "strings": [
                "Microsoft Windows",
                "Configuration Manager",
                "Settings",
                "Synthetic Goodware"
            ]
        }
    ]

    for i, sample in enumerate(
        samples,
        1
    ):

        filename = os.path.join(
            OUTPUT_DIR,
            f"goodware_{i:02d}.exe"
        )

        create_mock_pe(
            filename,
            sample["dlls"],
            sample["imports"],
            sample["strings"]
        )

    print(
        "\n[+] Generated 5 synthetic "
        "goodware PE files."
    )


if __name__ == "__main__":
    main()
