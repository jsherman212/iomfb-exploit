#ifndef KERNEL_HOOKS
#define KERNEL_HOOKS

#include <mach/kmod.h>
#include <stdint.h>

kern_return_t (*kernel_memory_allocate)(void *, uint64_t *, uint64_t,
        uint64_t, uint64_t, uint32_t);
kern_return_t _kernel_memory_allocate(void *map, uint64_t *addrp,
        uint64_t size, uint64_t mask, uint64_t flags, uint32_t tag);

#endif
