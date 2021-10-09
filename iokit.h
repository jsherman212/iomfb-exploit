#ifndef IOKIT_HEADER
#define IOKIT_HEADER

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <stdint.h>

typedef mach_port_t io_object_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_enumerator_t;
typedef io_object_t io_iterator_t;
typedef io_object_t io_registry_entry_t;
typedef io_object_t io_service_t;
typedef io_object_t io_registry_entry_t;
typedef char        io_name_t[128];
typedef char io_string_t[512];

#define IO_OBJECT_NULL  ((io_object_t) 0)

typedef uint32_t IOOptionBits;

/* IOKit/IOKitLib.h */
extern CFMutableDictionaryRef IORegistryEntryIDMatching(uint32_t service_id);
extern const mach_port_t kIOMasterPortDefault;

extern CFMutableDictionaryRef IOServiceMatching(const char *name);

extern io_service_t IOServiceGetMatchingService(mach_port_t masterPort,
        CFDictionaryRef matching);

extern kern_return_t IOServiceGetMatchingServices(mach_port_t, CFMutableDictionaryRef,
        io_iterator_t);

extern kern_return_t IORegistryEntryGetName(io_registry_entry_t entry, io_name_t name);

extern io_object_t IOIteratorNext(io_iterator_t iterator);

extern kern_return_t IOConnectSetNotificationPort(io_connect_t connect,
        uint32_t type, mach_port_t port, uintptr_t reference);

extern io_registry_entry_t IORegistryEntryFromPath(mach_port_t masterPort,
        const io_string_t path);

extern int IOIteratorIsValid(io_iterator_t);

extern kern_return_t IOObjectGetClass(io_object_t object, io_name_t className);

extern kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask,
        uint32_t type, io_connect_t *connect);

extern kern_return_t IOConnectMapMemory64(io_connect_t connect, uint32_t memoryType,
        mach_port_t intoTask, mach_vm_address_t *atAddress, mach_vm_size_t *ofSize,
        uint32_t options);

extern kern_return_t IOConnectUnmapMemory64(io_connect_t connect, uint32_t memoryType,
        task_port_t fromTask, mach_vm_address_t atAddress);

extern io_registry_entry_t IORegistryGetRootEntry(mach_port_t masterPort);

extern CFTypeRef IORegistryEntrySearchCFProperty(io_registry_entry_t entry,
        const io_name_t plane, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);

extern CFTypeRef IORegistryEntryCreateCFProperty(io_registry_entry_t entry,
        CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);

extern kern_return_t IOConnectCallScalarMethod(mach_port_t connection,
        uint32_t selector, const uint64_t *input, uint32_t inputCnt,
        uint64_t *output, uint32_t *outputCnt);

extern kern_return_t IOConnectCallStructMethod(mach_port_t connection,
        uint32_t selector, const void *inputStruct, size_t inputStructCnt,
        void *outputStruct, size_t *outputStructCnt);

extern kern_return_t IOConnectCallAsyncMethod(mach_port_t connection,
        uint32_t selector, mach_port_t wake_port, uint64_t *reference,
        uint32_t referenceCnt, const uint64_t *input, uint32_t inputCnt,
        const void *inputStruct, size_t inputStructCnt, uint64_t *output,
        uint32_t *outputCnt, void *outputStruct, size_t *outputStructCnt);

extern kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector,
        const uint64_t *input, uint32_t inputCnt, const void *inputStruct,
        size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt,
        void *outputStruct, size_t *outputStructCnt);



extern kern_return_t IOConnectTrap0(io_connect_t connect, uint32_t index);
extern kern_return_t IOConnectTrap1(io_connect_t connect, uint32_t index, uintptr_t p1);
extern kern_return_t IOConnectTrap2(io_connect_t connect, uint32_t index, uintptr_t p1,
        uintptr_t p2);
extern kern_return_t IOConnectTrap3(io_connect_t connect, uint32_t index, uintptr_t p1,
        uintptr_t p2, uintptr_t p3);
extern kern_return_t IOConnectTrap4(io_connect_t connect, uint32_t index, uintptr_t p1,
        uintptr_t p2, uintptr_t p3, uintptr_t p4);
extern kern_return_t IOConnectTrap5(io_connect_t connect, uint32_t index, uintptr_t p1,
        uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5);
extern kern_return_t IOConnectTrap6(io_connect_t connect, uint32_t index, uintptr_t p1,
        uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5, uintptr_t p6);

extern kern_return_t IOConnectAddClient(io_connect_t connect, io_connect_t client);

extern kern_return_t IOServiceClose(io_connect_t connect);

enum {
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,
    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,
    kOSSerializeEndCollection   = 0x80000000U,
    kOSSerializeBinarySignature = 0x000000d3U,
};

struct IOKitDiagnosticsParameters {
    size_t    size;
    uint64_t  value;
    uint32_t  options;
    uint32_t  tag;
    uint32_t  zsize;
    uint32_t  reserved[8];
};

typedef struct IOKitDiagnosticsParameters IOKitDiagnosticsParameters;

enum{
    kIOTrackingCallSiteBTs = 16,
};

struct IOTrackingCallSiteInfo {
    uint32_t          count;
    pid_t             addressPID;
    mach_vm_address_t address;
    mach_vm_size_t    size[2];
    pid_t             btPID;
    mach_vm_address_t bt[2][kIOTrackingCallSiteBTs];
};

enum{
    kIOTrackingExcludeNames      = 0x00000001,
};

enum{
    kIOTrackingGetTracking       = 0x00000001,
    kIOTrackingGetMappings       = 0x00000002,
    kIOTrackingResetTracking     = 0x00000003,
    kIOTrackingStartCapture      = 0x00000004,
    kIOTrackingStopCapture       = 0x00000005,
    kIOTrackingSetMinCaptureSize = 0x00000006,
    kIOTrackingLeaks             = 0x00000007,
    kIOTrackingInvalid           = 0xFFFFFFFE,
};
enum {
    kIODefaultMemoryType        = 0
};

enum {
    kIODefaultCache             = 0,
    kIOInhibitCache             = 1,
    kIOWriteThruCache           = 2,
    kIOCopybackCache            = 3,
    kIOWriteCombineCache        = 4,
    kIOCopybackInnerCache       = 5,
    kIOPostedWrite              = 6,
    kIORealTimeCache            = 7,
    kIOPostedReordered          = 8,
    kIOPostedCombinedReordered  = 9,
};

enum {
    kIOMapAnywhere                = 0x00000001,

    kIOMapCacheMask               = 0x00000f00,
    kIOMapCacheShift              = 8,
    kIOMapDefaultCache            = kIODefaultCache            << kIOMapCacheShift,
    kIOMapInhibitCache            = kIOInhibitCache            << kIOMapCacheShift,
    kIOMapWriteThruCache          = kIOWriteThruCache          << kIOMapCacheShift,
    kIOMapCopybackCache           = kIOCopybackCache           << kIOMapCacheShift,
    kIOMapWriteCombineCache       = kIOWriteCombineCache       << kIOMapCacheShift,
    kIOMapCopybackInnerCache      = kIOCopybackInnerCache      << kIOMapCacheShift,
    kIOMapPostedWrite             = kIOPostedWrite             << kIOMapCacheShift,
    kIOMapRealTimeCache           = kIORealTimeCache           << kIOMapCacheShift,
    kIOMapPostedReordered         = kIOPostedReordered         << kIOMapCacheShift,
    kIOMapPostedCombinedReordered = kIOPostedCombinedReordered << kIOMapCacheShift,

    kIOMapUserOptionsMask         = 0x00000fff,

    kIOMapReadOnly                = 0x00001000,

    kIOMapStatic                  = 0x01000000,
    kIOMapReference               = 0x02000000,
    kIOMapUnique                  = 0x04000000,
    kIOMapPrefault                = 0x10000000,
    kIOMapOverwrite               = 0x20000000
};
#endif
