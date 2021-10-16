#include <mach/kmod.h>
#include <stdbool.h>
#include <stdint.h>

void *g_osdata_kaddrs[8000];
uint64_t g_osdata_kaddrs_idx = 0;
bool g_record_osdata_kaddrs = false;

uint64_t kernel_slide = 0;

kern_return_t (*kernel_memory_allocate)(void *, uint64_t *, uint64_t,
        uint64_t, uint64_t, uint32_t);

kern_return_t _kernel_memory_allocate(void *map, uint64_t *addrp,
        uint64_t size, uint64_t mask, uint64_t flags, uint32_t tag){
    uint64_t caller = (uint64_t)__builtin_return_address(0) - kernel_slide;

    kern_return_t kret = kernel_memory_allocate(map, addrp, size, mask,
            flags, tag);

    /* if(caller == 0xfffffff007fc0f24){ */
    /* XXX iphone se 14.7 below */
    if(caller == 0xfffffff007658300){
        uint64_t osdata_mem = *addrp;

        if(size == 0x10000 && g_record_osdata_kaddrs){
            g_osdata_kaddrs[g_osdata_kaddrs_idx] = (void *)osdata_mem;
            g_osdata_kaddrs_idx++;
        }
    }

    return kret;
}
