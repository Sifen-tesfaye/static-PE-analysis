
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t read_u16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32(const unsigned char *p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static uint64_t read_u64(const unsigned char *p) {
    return (uint64_t)read_u32(p)
        | ((uint64_t)read_u32(p + 4) << 32);
}

static int has_bytes(size_t size, size_t offset, size_t count) {
    return offset <= size && count <= size - offset;
}

int main(int argc, char *argv[]) {
    FILE *file;
    unsigned char *data;
    long file_length;
    size_t size;
    uint32_t pe_offset;
    uint16_t machine, section_count, optional_size, characteristics;
    uint16_t magic;
    uint32_t entry_rva;
    uint64_t image_base;
    size_t optional_offset, section_table;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <PE-file>\n", argv[0]);
        return 2;
    }

    file = fopen(argv[1], "rb");
    if (file == NULL) {
        perror("Could not open file");
        return 1;
    }

    if (fseek(file, 0, SEEK_END) != 0 ||
        (file_length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Could not determine file size.\n");
        fclose(file);
        return 1;
    }

    size = (size_t)file_length;
    if ((long)size != file_length || size == 0) {
        fprintf(stderr, "Invalid or empty file.\n");
        fclose(file);
        return 1;
    }

    data = malloc(size);
    if (data == NULL) {
        fprintf(stderr, "Not enough memory to read file.\n");
        fclose(file);
        return 1;
    }

    if (fread(data, 1, size, file) != size) {
        fprintf(stderr, "Could not read complete file.\n");
        free(data);
        fclose(file);
        return 1;
    }
    fclose(file);

    printf("File size: %zu bytes\n", size);

    if (size < 64 || data[0] != 'M' || data[1] != 'Z') {
        puts("Invalid DOS header: missing MZ signature.");
        free(data);
        return 1;
    }

    pe_offset = read_u32(data + 0x3C);
    printf("DOS signature: MZ\n");
    printf("PE header offset: 0x%X\n", pe_offset);

    if (!has_bytes(size, pe_offset, 24) ||
        memcmp(data + pe_offset, "PE\0\0", 4) != 0) {
        puts("Invalid or incomplete PE header.");
        free(data);
        return 1;
    }

    machine = read_u16(data + pe_offset + 4);
    section_count = read_u16(data + pe_offset + 6);
    printf("COFF timestamp field: %u\n",
           read_u32(data + pe_offset + 8));
    optional_size = read_u16(data + pe_offset + 20);
    characteristics = read_u16(data + pe_offset + 22);
    optional_offset = (size_t)pe_offset + 24;

    if (!has_bytes(size, optional_offset, optional_size) ||
        optional_size < 2) {
        puts("Invalid optional header.");
        free(data);
        return 1;
    }

    magic = read_u16(data + optional_offset);

    if (magic == 0x10B) {
        if (optional_size < 96) {
            puts("PE32 optional header is too short.");
            free(data);
            return 1;
        }
        puts("PE format: PE32");
        image_base = read_u32(data + optional_offset + 28);
    } else if (magic == 0x20B) {
        if (optional_size < 112) {
            puts("PE32+ optional header is too short.");
            free(data);
            return 1;
        }
        puts("PE format: PE32+");
        image_base = read_u64(data + optional_offset + 24);
    } else {
        printf("Unknown optional-header magic: 0x%04X\n", magic);
        free(data);
        return 1;
    }

    entry_rva = read_u32(data + optional_offset + 16);
    section_table = optional_offset + optional_size;

    printf("Machine: 0x%04X\n", machine);
    printf("Number of sections: %u\n", section_count);
    printf("Optional-header size: %u\n", optional_size);
    printf("Characteristics: 0x%04X\n", characteristics);
    printf("Entry point RVA: 0x%X\n", entry_rva);
    printf("Image base: 0x%llX\n",
           (unsigned long long)image_base);
    printf("Preferred entry point VA: 0x%llX\n",
           (unsigned long long)(image_base + entry_rva));

    if (!has_bytes(size, section_table, (size_t)section_count * 40)) {
        puts("Invalid section table: incomplete or out of bounds.");
        free(data);
        return 1;
    }

    puts("\nSections:");
    printf("%-10s %12s %16s %12s %12s %16s\n",
           "Name", "VirtualSize", "VirtualAddress",
           "RawSize", "RawOffset", "Characteristics");

    for (unsigned int i = 0; i < section_count; i++) {
        const unsigned char *s = data + section_table + i * 40;
        char name[9];
        uint32_t virtual_size = read_u32(s + 8);
        uint32_t virtual_address = read_u32(s + 12);
        uint32_t raw_size = read_u32(s + 16);
        uint32_t raw_offset = read_u32(s + 20);
        uint32_t flags = read_u32(s + 36);

        memcpy(name, s, 8);
        name[8] = '\0';

        printf("%-10s %12u 0x%08X %12u 0x%08X 0x%08X\n",
               name, virtual_size, virtual_address,
               raw_size, raw_offset, flags);

        if (raw_size &&
            !has_bytes(size, raw_offset, raw_size)) {
            printf("  WARNING: %s raw data extends beyond the file.\n",
                   name);
        }
    }

    free(data);
    return 0;
}

