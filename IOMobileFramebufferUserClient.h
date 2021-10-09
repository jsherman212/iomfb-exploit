
#ifndef IOMobileFramebufferUserClient_GUARD
#define IOMobileFramebufferUserClient_GUARD

void IOMobileFramebufferUserClient_tests(void);

/* extern uint64_t g_mach_port_kaddr; */
extern void *g_test_port;
extern bool g_dump_mqueue_logs;
extern bool g_dump_peek_logs;
extern bool g_log_queue_move_entry_gated;

extern uint64_t g_right_port_kaddr;

extern uint64_t g_osdata_kaddr;

#endif
            
