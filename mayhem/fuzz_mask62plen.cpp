#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
extern "C" int mask62plen(const u_char *);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    u_char *mask = (u_char *)malloc(sizeof(u_char) * 16);
    provider.ConsumeData(mask, sizeof(u_char) * 16);
    mask62plen(mask);
    free(mask);

    return 0;
}