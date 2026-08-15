import struct

def create_variant_pe(index):
    output_filename = f"sample_{index}.exe"
    
    # 1. DOS Header + Stub
    dos_header = bytearray(0x40)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, 0x80)
    
    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
    dos_padding = b'\x00' * (0x80 - len(dos_header) - len(dos_stub))
    
    # 2. NT Headers
    pe_sig = b'PE\x00\x00'
    
    # COFF File Header (Varying timestamp slightly per variant)
    file_header = struct.pack(
        '<HHIIIHH',
        0x014c,              # Machine: x86
        3,                   # Number of Sections (.text, .rdata, .data)
        0x66BCCD00 + index,  # Unique Timestamp per variant
        0, 0,                # PointerToSymbolTable, NumberOfSymbols
        224,                 # SizeOfOptionalHeader
        0x0102               # Characteristics
    )
    
    # Optional Header (PE32) - 30 items matching 30 format specifiers
    opt_header = struct.pack(
        '<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII',
        0x010b,      # Magic: PE32
        14, 0,       # Major/Minor Linker Version
        0x1000,      # SizeOfCode
        0x1000,      # SizeOfInitializedData
        0,           # SizeOfUninitializedData
        0x1000,      # AddressOfEntryPoint
        0x1000,      # BaseOfCode
        0x2000,      # BaseOfData
        0x00400000,  # ImageBase
        0x1000,      # SectionAlignment
        0x0200,      # FileAlignment
        6, 0,        # Major/Minor OS Version
        0, 0,        # Major/Minor Image Version
        6, 0,        # Major/Minor Subsystem Version
        0,           # Win32VersionValue
        0x4000,      # SizeOfImage
        0x0400,      # SizeOfHeaders
        0,           # CheckSum
        2,           # Subsystem: Windows GUI
        0x8140,      # DllCharacteristics
        0x100000, 0x1000, # Stack Reserve / Commit
        0x100000, 0x1000, # Heap Reserve / Commit
        0,           # LoaderFlags
        16           # NumberOfRvaAndSizes
    )
    
    data_dirs = bytearray(16 * 8)
    struct.pack_into('<II', data_dirs, 1 * 8, 0x2000, 0x3C)  # Import Directory
    struct.pack_into('<II', data_dirs, 12 * 8, 0x2050, 0x10) # IAT Directory
    
    # Section Headers
    sec_text = struct.pack('<8sIIIIIIHHI', b'.text\x00\x00\x00', 0x1000, 0x1000, 0x0200, 0x0400, 0, 0, 0, 0, 0x60000020)
    sec_rdata = struct.pack('<8sIIIIIIHHI', b'.rdata\x00\x00', 0x1000, 0x2000, 0x0200, 0x0600, 0, 0, 0, 0, 0x40000040)
    sec_data = struct.pack('<8sIIIIIIHHI', b'.data\x00\x00\x00', 0x1000, 0x3000, 0x0200, 0x0800, 0, 0, 0, 0, 0xC0000040)

    headers_raw = dos_header + dos_stub + dos_padding + pe_sig + file_header + opt_header + data_dirs + sec_text + sec_rdata + sec_data
    headers_padding = b'\x00' * (0x0400 - len(headers_raw))
    
    # 3. Section Data Payload
    text_payload = (
        b"\x6A\x00"                         # push 0
        b"\x68\x10\x30\x40\x00"             # push string pointer
        b"\x68\x00\x30\x40\x00"             # push string pointer
        b"\x6A\x00"                         # push 0
        b"\xFF\x15\x50\x20\x40\x00"         # call MessageBoxA
        b"\x6A\x00"                         # push 0
        b"\xFF\x15\x54\x20\x40\x00"         # call ExitProcess
    )
    text_data = text_payload + b'\x00' * (0x0200 - len(text_payload))

    rdata = bytearray(0x0200)
    struct.pack_into('<IIIII', rdata, 0x00, 0x203C, 0, 0, 0x2070, 0x2050)
    struct.pack_into('<IIIII', rdata, 0x14, 0x2044, 0, 0, 0x207C, 0x2054)

    struct.pack_into('<II', rdata, 0x3C, 0x2088, 0)
    struct.pack_into('<II', rdata, 0x44, 0x2096, 0)
    struct.pack_into('<II', rdata, 0x50, 0x2088, 0)
    struct.pack_into('<II', rdata, 0x54, 0x2096, 0)

    struct.pack_into('12s', rdata, 0x70, b'USER32.dll\x00')
    struct.pack_into('13s', rdata, 0x7C, b'KERNEL32.dll\x00')
    struct.pack_into('<H12s', rdata, 0x88, 0, b'MessageBoxA\x00')
    struct.pack_into('<H12s', rdata, 0x96, 0, b'ExitProcess\x00')

    # --- Mixed Data Section (Shared + Unique Strings) ---
    shared_tag = b"YARA_Test_Family_Alpha\x00"
    unique_string = f"Variant_ID_{index}_Payload\x00".encode('utf-8')
    
    data_payload = (
        shared_tag +                    # Matches across all files
        b"\x00" * (16 - len(shared_tag) % 16) +
        unique_string +                 # Unique to this specific file
        b"\x00" * (32 - len(unique_string) % 32) +
        f"Config_Port_{8000 + index}\x00".encode('utf-8') # Another unique attribute
    )
    data_section = data_payload + b'\x00' * (0x0200 - len(data_payload))

    # 4. Write File
    full_pe_bytes = headers_raw + headers_padding + text_data + rdata + data_section
    with open(output_filename, "wb") as f:
        f.write(full_pe_bytes)
        
    print(f"[+] Generated: {output_filename} (Shared Tag: present, Unique ID: Variant_{index})")

if __name__ == "__main__":
    for i in range(1, 6):
        create_variant_pe(i)
    print("\n[+] Successfully generated 5 variant PE files!")
