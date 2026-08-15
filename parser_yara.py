#!/usr/bin/env python3
"""
Simple PE File Parser
Extracts: printable strings, import tables, section names, PE headers, and rich header
"""

import pefile
import sys
import os
import re
import datetime

def parse_pe_file(filepath):
    """Parse a Windows PE file and extract all requested information"""
    
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found")
        return
    
    try:
        pe = pefile.PE(filepath)
    except Exception as e:
        print(f"Error loading PE file: {e}")
        return
    
    print("=" * 80)
    print(f"Analyzing: {os.path.basename(filepath)}")
    print("=" * 80)
    
    # 1. PE Header Fields
    print("\n[1] PE HEADER FIELDS")
    print("-" * 40)
    print(f"Machine: {hex(pe.FILE_HEADER.Machine)} ({pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, 'Unknown')})")
    print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
    
    # Convert timestamp to readable format
    timestamp = pe.FILE_HEADER.TimeDateStamp
    try:
        time_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        time_str = "Invalid timestamp"
    print(f"Time Date Stamp: {timestamp} ({time_str})")
    
    print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")
    
    if hasattr(pe, 'OPTIONAL_HEADER'):
        print(f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"Size of Code: {pe.OPTIONAL_HEADER.SizeOfCode}")
        print(f"Size of Image: {pe.OPTIONAL_HEADER.SizeOfImage}")
        print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
        print(f"DLL Characteristics: {hex(pe.OPTIONAL_HEADER.DllCharacteristics)}")
    
    # 2. Section Names
    print("\n[2] SECTION NAMES")
    print("-" * 40)
    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        print(f"  {section_name} - Size: {section.SizeOfRawData} bytes, Virtual Size: {section.Misc_VirtualSize}")
    
    # 3. Import Tables (DLLs and Functions)
    print("\n[3] IMPORT TABLES (DLLs + Function Names)")
    print("-" * 40)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            print(f"\n  DLL: {dll_name}")
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    print(f"    - {func_name}")
                else:
                    print(f"    - Ordinal: {imp.ordinal}")
    else:
        print("  No import table found")
    
    # 4. Printable Strings
    print("\n[4] PRINTABLE STRINGS")
    print("-" * 40)
    printable_strings = extract_printable_strings(pe)
    if printable_strings:
        count = 0
        for s in printable_strings[:50]:  # Limit to 50 strings for readability
            print(f"  {s}")
            count += 1
        if len(printable_strings) > 50:
            print(f"  ... and {len(printable_strings) - 50} more strings")
    else:
        print("  No printable strings found")
    
    # 5. Rich Header
    print("\n[5] RICH HEADER")
    print("-" * 40)
    try:
        if hasattr(pe, 'RICH_HEADER'):
            rich_header = pe.RICH_HEADER
            print(f"  Count of entries: {len(rich_header.values)}")
            print(f"  Checksum: {hex(rich_header.checksum)}")
            print("\n  Compiler/Version Information:")
            for i, value in enumerate(rich_header.values[:10]):  # Show first 10 entries
                # Decode the rich header value
                product_id = value >> 16
                version = value & 0xFFFF
                # Try to map product ID to a known compiler
                product_names = {
                    0: "Visual C++",
                    1: "Microsoft C++",
                    2: "Borland",
                    3: "Turbo C",
                    4: "Watcom",
                    5: "Intel",
                    6: "Digital Mars",
                    0x2C: "Visual Studio 2013",
                    0x5A: "Visual Studio 2015",
                    0x5B: "Visual Studio 2017",
                    0x5C: "Visual Studio 2019",
                }
                product_name = product_names.get(product_id, f"Unknown (0x{product_id:X})")
                version_major = version >> 8
                version_minor = version & 0xFF
                print(f"    Entry {i+1}: {product_name} version {version_major}.{version_minor}")
            if len(rich_header.values) > 10:
                print(f"    ... and {len(rich_header.values) - 10} more entries")
        else:
            print("  No rich header found")
    except Exception as e:
        print(f"  Error parsing rich header: {e}")
    
    # 6. Additional info - File size
    print("\n[6] ADDITIONAL INFO")
    print("-" * 40)
    file_size = os.path.getsize(filepath)
    print(f"  File Size: {file_size} bytes ({file_size / 1024:.2f} KB)")
    
    # Check for exports
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print(f"  Has Export Table: Yes")
    else:
        print(f"  Has Export Table: No")
    
    print("\n" + "=" * 80)
    print("Analysis complete!")
    print("=" * 80)

def extract_printable_strings(pe):
    """Extract printable strings from the PE file data"""
    strings = []
    min_length = 4  # Minimum string length to extract
    
    try:
        # Read the entire file data
        with open(pe.filename, 'rb') as f:
            data = f.read()
        
        # Find all ASCII strings
        # Pattern matches printable ASCII characters
        pattern = rb'[A-Za-z0-9 !"#$%&\'()*+,\-./:;<=>?@[\\\]^_`{|}~]{4,}'
        matches = re.findall(pattern, data)
        
        # Decode and filter
        for match in matches:
            try:
                s = match.decode('ascii', errors='ignore')
                # Filter out strings that look like binary data
                if len(s) >= min_length and not s.isdigit() and not all(c in '0123456789ABCDEFabcdef' for c in s[:8]):
                    strings.append(s)
            except:
                continue
        
        # Remove duplicates and sort by length (longest first)
        strings = sorted(set(strings), key=len, reverse=True)
        
    except Exception as e:
        print(f"Error extracting strings: {e}")
    
    return strings

def main():
    if len(sys.argv) < 2:
        print("Usage: python pe_parser.py <path_to_pe_file.exe>")
        print("Example: python pe_parser.py MessageBox.exe")
        sys.exit(1)
    
    filepath = sys.argv[1]
    parse_pe_file(filepath)

if __name__ == "__main__":
    main()
