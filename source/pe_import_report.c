
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define MAX_IMPORTS 4096
#define DOS_HEADER_SIZE 64
#define PE_FIXED_HEADER_SIZE 24
#define SECTION_HEADER_SIZE 40
#define MAX_FILE_SIZE (256ULL * 1024 * 1024)

static uint16_t u16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static uint64_t u64(const unsigned char *p) {
    return (uint64_t)u32(p)
        | ((uint64_t)u32(p + 4) << 32);
}

static int has_bytes(size_t size, size_t off, size_t count) {
    return off <= size && count <= size - off;
}

static int rva_to_offset(
    uint32_t rva,
    size_t size,
    const unsigned char *data,
    size_t section_table,
    uint16_t section_count,
    size_t *result
) {
    if (result == NULL ||
        !has_bytes(size, section_table,
                   (size_t)section_count * SECTION_HEADER_SIZE)) {
        return 0;
    }

    for (uint16_t i = 0; i < section_count; i++) {
        const unsigned char *s =
            data + section_table + (size_t)i * SECTION_HEADER_SIZE;

        uint32_t va = u32(s + 12);
        uint32_t raw_size = u32(s + 16);
        uint32_t raw_off = u32(s + 20);

        if (raw_size == 0) {
            continue;
        }

        if (!has_bytes(size, (size_t)raw_off, (size_t)raw_size)) {
            continue;
        }

        if (rva >= va &&
            (uint64_t)rva < (uint64_t)va + raw_size) {
            size_t delta = (size_t)(rva - va);

            if (delta > SIZE_MAX - (size_t)raw_off) {
                return 0;
            }

            *result = (size_t)raw_off + delta;
            return 1;
        }
    }

    return 0;
}

static int read_string(
    const unsigned char *data,
    size_t size,
    size_t off,
    char *out,
    size_t capacity
) {
    if (capacity == 0 || off >= size) {
        return 0;
    }

    size_t available = size - off;
    size_t limit = available < capacity ? available : capacity;

    for (size_t i = 0; i < limit; i++) {
        out[i] = (char)data[off + i];

        if (out[i] == '\0') {
            return 1;
        }
    }

    out[capacity - 1] = '\0';
    return 0;
}

int main(int argc, char **argv) {
    FILE *f = NULL;
    unsigned char *data = NULL;
    long file_len;
    size_t size, opt, sec, import_off;
    size_t dir_off;
    uint32_t pe, import_rva, import_size;
    uint16_t sections, opt_size, magic;
    int status = 1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <PE-file>\n", argv[0]);
        return 2;
    }

    f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror("fopen");
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0 ||
        (file_len = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Could not determine file size.\n");
        goto done;
    }

    if (file_len == 0 ||
        (uint64_t)file_len > MAX_FILE_SIZE) {
        fprintf(stderr, "Empty or oversized input file.\n");
        goto done;
    }

    size = (size_t)file_len;

    if ((long)size != file_len) {
        fprintf(stderr, "Unsupported file size.\n");
        goto done;
    }

    data = malloc(size);
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        goto done;
    }

    if (fread(data, 1, size, f) != size) {
        fprintf(stderr, "Could not read complete file.\n");
        goto done;
    }

    fclose(f);
    f = NULL;

    if (size < DOS_HEADER_SIZE ||
        data[0] != 'M' || data[1] != 'Z') {
        fprintf(stderr, "Invalid DOS header.\n");
        goto done;
    }

    pe = u32(data + 0x3C);

    if (!has_bytes(size, (size_t)pe, PE_FIXED_HEADER_SIZE) ||
        memcmp(data + pe, "PE\0\0", 4) != 0) {
        fprintf(stderr, "Invalid PE header.\n");
        goto done;
    }

    sections = u16(data + pe + 6);
    opt_size = u16(data + pe + 20);
    opt = (size_t)pe + PE_FIXED_HEADER_SIZE;

    if (!has_bytes(size, opt, opt_size) || opt_size < 2) {
        fprintf(stderr, "Invalid optional header.\n");
        goto done;
    }

    magic = u16(data + opt);

    if (magic == 0x10B) {
        dir_off = 96;
    } else if (magic == 0x20B) {
        dir_off = 112;
    } else {
        fprintf(stderr, "Unsupported optional-header magic.\n");
        goto done;
    }

    if (opt_size < dir_off + 16 ||
        !has_bytes(size, opt, dir_off + 16)) {
        fprintf(stderr,
                "Optional header lacks import-directory fields.\n");
        goto done;
    }

    import_rva = u32(data + opt + dir_off + 8);
    import_size = u32(data + opt + dir_off + 12);
    sec = opt + opt_size;

    if (!has_bytes(size, sec,
                   (size_t)sections * SECTION_HEADER_SIZE)) {
        fprintf(stderr, "Section table is incomplete.\n");
        goto done;
    }

    printf("PE format: %s\n",
           magic == 0x10B ? "PE32" : "PE32+");
    printf("Import Directory RVA: 0x%08X\n", import_rva);
    printf("Import Directory size: %u bytes\n", import_size);

    if (import_rva == 0 && import_size == 0) {
        puts("No import directory declared.");
        status = 0;
        goto done;
    }

    if (import_rva == 0 || import_size == 0) {
        fprintf(stderr, "Inconsistent import-directory fields.\n");
        goto done;
    }

    if (!rva_to_offset(import_rva, size, data, sec,
                       sections, &import_off)) {
        fprintf(stderr,
                "Import directory RVA does not map to valid file data.\n");
        goto done;
    }

    /*
     * Require the declared import-directory bytes to fit in the file.
     * This also prevents descriptor iteration beyond the declared range.
     */
    if (import_size < 20 ||
        !has_bytes(size, import_off, import_size)) {
        fprintf(stderr, "Invalid import-directory size or range.\n");
        goto done;
    }

    puts("\nImported DLLs and functions:");

    {
        size_t descriptor = import_off;
        size_t descriptors_seen = 0;
        size_t descriptors_limit = import_size / 20;
        int terminated = 0;

        while (descriptors_seen < descriptors_limit &&
               has_bytes(size, descriptor, 20)) {
            const unsigned char *d = data + descriptor;

            uint32_t oft = u32(d);
            uint32_t name_rva = u32(d + 12);
            uint32_t ft = u32(d + 16);
            size_t name_off;

            if (u32(d) == 0 &&
                u32(d + 4) == 0 &&
                u32(d + 8) == 0 &&
                name_rva == 0 &&
                ft == 0) {
                terminated = 1;
                break;
            }

            if (!rva_to_offset(name_rva, size, data, sec,
                               sections, &name_off)) {
                fprintf(stderr, "Invalid DLL-name RVA.\n");
                goto done;
            }

            {
                char dll[260];

                if (!read_string(data, size, name_off,
                                 dll, sizeof dll)) {
                    fprintf(stderr,
                            "Invalid or unterminated DLL name.\n");
                    goto done;
                }

                printf("\nDLL: %s\n", dll);
            }

            {
                uint32_t thunk_rva = oft ? oft : ft;
                size_t thunk_off;
                size_t index = 0;
                size_t width = magic == 0x10B ? 4 : 8;
                int thunk_done = 0;

                if (!rva_to_offset(thunk_rva, size, data, sec,
                                   sections, &thunk_off)) {
                    fprintf(stderr, "Invalid import-thunk RVA.\n");
                    goto done;
                }

                while (index < MAX_IMPORTS &&
                       has_bytes(size, thunk_off, width)) {
                    uint64_t thunk = width == 4
                        ? u32(data + thunk_off)
                        : u64(data + thunk_off);

                    if (thunk == 0) {
                        thunk_done = 1;
                        break;
                    }

                    if (width == 4
                        ? (thunk & 0x80000000ULL) != 0
                        : (thunk & 0x8000000000000000ULL) != 0) {
                        printf("  Import by ordinal: %llu\n",
                               (unsigned long long)(thunk & 0xFFFF));
                    } else {
                        size_t hint_name_off;

                        /*
                         * Import-by-name entries contain a 32-bit RVA.
                         * Reject larger PE32+ values instead of truncating.
                         */
                        if (thunk > UINT32_MAX) {
                            fprintf(stderr,
                                    "Import-name RVA exceeds 32-bit range.\n");
                            goto done;
                        }

                        uint32_t hint_name_rva = (uint32_t)thunk;

                        if (!rva_to_offset(hint_name_rva, size, data,
                                           sec, sections,
                                           &hint_name_off) ||
                            !has_bytes(size, hint_name_off, 3)) {
                            fprintf(stderr, "Invalid import-name RVA.\n");
                            goto done;
                        }

                        {
                            char function[512];

                            if (!read_string(data, size,
                                             hint_name_off + 2,
                                             function,
                                             sizeof function)) {
                                fprintf(stderr, "Invalid import name.\n");
                                goto done;
                            }

                            printf("  %s\n", function);
                        }
                    }

                    if (thunk_off > SIZE_MAX - width) {
                        fprintf(stderr, "Thunk offset overflow.\n");
                        goto done;
                    }

                    thunk_off += width;
                    index++;
                }

                if (!thunk_done) {
                    fprintf(stderr,
                            "Unterminated or incomplete thunk table.\n");
                    goto done;
                }
            }

            if (descriptor > SIZE_MAX - 20) {
                fprintf(stderr, "Descriptor offset overflow.\n");
                goto done;
            }

            descriptor += 20;
            descriptors_seen++;
        }

        if (!terminated) {
            fprintf(stderr, "Missing import-descriptor terminator.\n");
            goto done;
        }
    }

    status = 0;

done:
    if (f != NULL) {
        fclose(f);
    }

    free(data);
    return status;
}

