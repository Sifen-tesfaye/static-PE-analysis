
import struct
import sys
from pathlib import Path


def inspect_pe(file_path):
    data = Path(file_path).read_bytes()
    size = len(data)
    print(f"File size: {size} bytes")

    # Validate DOS header
    if size < 64 or data[:2] != b"MZ":
        print("Invalid DOS header: missing MZ signature.")
        return

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    print("DOS signature: MZ")
    print(f"PE header offset: 0x{pe_offset:X}")

    # Validate PE signature and COFF header
    if pe_offset > size or size - pe_offset < 24:
        print("Invalid PE offset: incomplete PE/COFF header.")
        return

    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        print("Missing PE signature.")
        return

    (
        machine,
        section_count,
        timestamp,
        _,
        _,
        optional_size,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)

    optional_offset = pe_offset + 24

    # Validate optional-header bounds
    if optional_size < 2 or optional_size > size - optional_offset:
        print("Invalid optional header: missing or out of bounds.")
        return

    magic = struct.unpack_from("<H", data, optional_offset)[0]

    if magic == 0x10B:
        pe_type = "PE32"
        min_size = 96
        image_base_offset = 28
        image_base_format = "<I"
    elif magic == 0x20B:
        pe_type = "PE32+"
        min_size = 112
        image_base_offset = 24
        image_base_format = "<Q"
    else:
        print(f"Unknown optional-header magic: 0x{magic:04X}")
        return

    if optional_size < min_size:
        print("Invalid optional header: too short.")
        return

    entry_rva = struct.unpack_from(
        "<I", data, optional_offset + 16
    )[0]

    image_base = struct.unpack_from(
        image_base_format,
        data,
        optional_offset + image_base_offset,
    )[0]

    print(f"PE format: {pe_type}")
    print(f"Machine: 0x{machine:04X}")
    print(f"Number of sections: {section_count}")
    print(f"COFF timestamp field: {timestamp}")
    print(f"Optional-header size: {optional_size}")
    print(f"Characteristics: 0x{characteristics:04X}")
    print(f"Entry point RVA: 0x{entry_rva:X}")
    print(f"Image base: 0x{image_base:X}")
    print(f"Preferred entry point VA: 0x{image_base + entry_rva:X}")

    # Validate section table
    section_table = optional_offset + optional_size

    if section_table > size or section_count > (size - section_table) // 40:
        print("Invalid section table: incomplete or out of bounds.")
        return

    if section_count == 0:
        print("No sections to display.")
        return

    print("\nSections:")
    print(
        f"{'Name':<10} {'VirtualSize':>12} "
        f"{'VirtualAddress':>16} {'RawSize':>12} "
        f"{'RawOffset':>12} {'Characteristics':>16}"
    )

    for i in range(section_count):
        offset = section_table + i * 40

        (
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            _,
            _,
            _,
            _,
            flags,
        ) = struct.unpack_from("<8sIIIIIIHHI", data, offset)

        name = name.split(b"\0", 1)[0].decode(
            "ascii", errors="replace"
        )

        print(
            f"{name:<10} {virtual_size:12} "
            f"0x{virtual_address:08X} {raw_size:12} "
            f"0x{raw_offset:08X} 0x{flags:08X}"
        )

        if raw_size and (
            raw_offset > size or raw_size > size - raw_offset
        ):
            print(f"  WARNING: {name} raw data extends beyond the file.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file>")
        raise SystemExit(2)

    try:
        inspect_pe(sys.argv[1])
    except (OSError, struct.error) as exc:
        print(f"Could not inspect file: {exc}")

