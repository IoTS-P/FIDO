
#include <stdint.h>
#include <unicorn/unicorn.h>
#ifndef DATA_TRACKER_H
#define DATA_TRACKER_H
// 定义DataTracker结构体
typedef struct DataTracker {
    uint32_t dr; // 数据寄存器的地址
    uint32_t callread_pc; // 调用read函数的pc
    uint32_t read_pc; // 在read函数中调用dr的pc
    uint32_t buffer_addr; // 由dr反映的地址
    uint32_t irq_pc; // irq处理程序的pc
    uint32_t avail_pc; // 检查rx缓冲区可用性的pc（由irq处理程序或read_pc计算）
    uint32_t rx_head; // 指向rx缓冲区的头部指针
    uint32_t rx_tail; // 指向rx缓冲区的尾部指针
    short buffer_len; // 缓冲区长度
    short buffer_min_len; // 缓冲区最小长度
    short irq_num;
    char consume_pcs[256]; // JSON fragment for consume_pc_set
    // fifo设置，头尾指针指向fuzz的数据
    uint8_t fifo[4096];
    short fifo_head;
    short fifo_tail;
    int interrupt_times;
} DataTracker;

// Pending (unrecognized) DR tracking
#define MAX_PENDING_DRS 128
#define MAX_DR_ADDRS 256
#define MAX_SR_ADDRS 256
#define MAX_DISCOVERY_ADDRS 1024
#define MAX_AVAIL_HOOKS 200
#define MAX_PENDING_HOOKS 128

extern DataTracker *pending_dt_array;
extern short pending_dt_array_index;

extern uint32_t g_all_dr_addrs[MAX_DR_ADDRS];
extern int g_num_dr_addrs;
extern uint32_t g_all_sr_addrs[MAX_SR_ADDRS];
extern int g_num_sr_addrs;

extern bool g_in_discovery_mode;
extern uint32_t g_discovery_dr;
extern uint32_t g_discovery_taint;
extern uint32_t g_discovery_irq_pc;
extern uint32_t g_discovery_addr_list[MAX_DISCOVERY_ADDRS];
extern int g_discovery_addr_count;
extern uint32_t g_discovery_buffer_addr;
extern uc_hook g_discovery_mem_read_hook;
extern uc_hook g_discovery_mem_write_hook;
extern bool g_discovery_occurred;
extern char g_json_file_path[512];

// Parallel buffer fill + read_pc capture
extern uint32_t g_discovery_read_pc;
extern uint32_t g_discovery_callread_pc;
extern uc_hook g_discovery_buffer_read_hook;
extern bool g_read_pc_done;
extern bool g_buffer_fill_active;
extern bool g_buffer_fill_done;
extern bool g_read_pc_done;
extern uint32_t g_fill_irq_num;
// Chain tracking
extern uint32_t g_chain_min;
extern uint32_t g_chain_max;
extern int g_chain_extend_count;
extern int g_consecutive_miss;
extern int g_chain_idle_bb;

// Hook handle tracking for per-round cleanup
extern uc_hook g_avail_hook_handles[MAX_AVAIL_HOOKS];
extern int g_num_avail_hooks;
extern uc_hook g_pending_hook_handles[MAX_PENDING_HOOKS];
extern int g_num_pending_hooks;

// Forward declarations for discovery callbacks (in native_hooks.c)
void hook_pending_dr_read_after(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);
void hook_discovery_mem_write(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);
void hook_discovery_mem_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);
void hook_phase1_buffer_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);

#endif