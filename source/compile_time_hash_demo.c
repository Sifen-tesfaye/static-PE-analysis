#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Harmless teaching example:
 * hash fixed strings at compile time, then compare with a
 * runtime reference implementation. This does not resolve APIs.
 */

#define HASH_STEP(h, c) (((h) ^ (uint32_t)(c)) * UINT32_C(16777619))
#define HASH4(s, h) HASH_STEP(HASH_STEP(HASH_STEP(HASH_STEP((h), (s)[0]), (s)[1]), (s)[2]), (s)[3])

#define HASH_INIT UINT32_C(2166136261)

static uint32_t hash_runtime(const char *s)
{
    uint32_t h = HASH_INIT;

    while (*s != '\0') {
        h = (h ^ (unsigned char)*s) * UINT32_C(16777619);
        ++s;
    }

    return h;
}

int main(void)
{
    /*
     * Four-character examples keep this demonstration simple.
     * HASH4 expands the four characters during compilation.
     */
    const uint32_t compile_time_value = HASH4("TEST", HASH_INIT);
    const uint32_t runtime_value = hash_runtime("TEST");

    printf("Input: TEST\n");
    printf("Compile-time hash: 0x%08X\n", compile_time_value);
    printf("Runtime reference: 0x%08X\n", runtime_value);
    printf("Comparison: %s\n",
           compile_time_value == runtime_value ? "PASS" : "FAIL");

    return compile_time_value == runtime_value ? 0 : 1;
}
