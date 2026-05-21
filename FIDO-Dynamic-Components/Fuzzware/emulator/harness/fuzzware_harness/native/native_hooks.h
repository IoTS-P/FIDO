#ifndef NATIVE_HOOKS_H
#define NATIVE_HOOKS_H

#include <stdbool.h>
#include "state_snapshotting.h"
#include "uc_snapshot.h"
#include "ufuzz_adapter/data_tracker.h"
#include "unicorn/unicorn.h"
// #define DEBUG
// #define DEBUG_STATE_RESTORE
#define DEBUG_SYSTICK
// #define DEBUG_TIMER

// #define DEBUG_INJECT_TIMER
// #define DEBUG_TIMER_TICKS
// #define DEBUG_NVIC 
// #define DEBUG_INTERRUPT_TRIGGERS
// #define DEBUG_STATE_SNAPSHOTTING

#define DEBUG_TIMER_TIMEOUT 100

extern int do_print_exit_info;
extern bool is_irq_managed_by_dt(int irq_num);
extern uint32_t num_mmio_regions;
extern uint64_t *mmio_region_starts;
extern uint64_t *mmio_region_ends;
extern short blocklist_interrupt[64];
extern short blocklist_interrupt_index;

struct linear_mmio_model_config {
  uint32_t step;
  uint32_t val;
};

struct constant_mmio_model_config {
  uint32_t val;
};

struct bitextract_mmio_model_config {
  uint8_t byte_size;
  uint8_t left_shift;
  uint8_t mask_hamming_weight;
  uint32_t mask;
};

struct value_set_mmio_model_config {
  uint32_t num_vals;
  uint32_t *values;
};

struct mmio_callback {
  uint64_t start;
  uint64_t end;
  uint32_t pc;
  void *user_data;
  uc_cb_hookmem_t callback;
};

typedef void (*exit_hook_t)(int, int);
typedef void (*mmio_region_added_cb_t)(uint64_t, uint64_t);

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void hook_block_exit_at(uc_engine *uc, uint64_t address, uint32_t size,
                        void *user_data);
void do_exit(uc_engine *uc, uc_err err);
void force_crash(uc_engine *uc, uc_err error);
void add_exit_hook(exit_hook_t hook);
uc_err load_fuzz(const char *path);
int avail_cnt(uint64_t address);

/**
 * Returns 0 upon success, 1 if no input is present.
 **/
bool get_fuzz(uc_engine *uc, uint8_t *buf, unsigned int size);

/**
 * Version handing out a pointer into the fuzz input buffer instead of copying
 *contents. One use case for this is to avoid excessive copying on the c->python
 *boundary.
 **/
uint8_t *get_fuzz_ptr(uc_engine *uc, uint32_t size);

/**
 * Get the current number of fuzzing bytes consumed
 **/
uint32_t fuzz_consumed();
uint32_t fuzz_remaining();

uint32_t get_latest_mmio_fuzz_access_size();
uint32_t get_latest_mmio_fuzz_access_index();

uc_err init(uc_engine *uc, exit_hook_t p_exit_hook, int p_num_mmio_regions,
            uint64_t *p_mmio_starts, uint64_t *p_mmio_ends,
            void *p_py_default_mmio_user_data, uint32_t num_exit_at_bbls,
            uint64_t *exit_at_bbls, uint32_t exit_at_hit_num,
            int p_do_print_exit_info, uint64_t fuzz_consumption_timeout,
            uint64_t p_instr_limit);
uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end);
uc_err add_mmio_subregion_handler(uc_engine *uc, uc_cb_hookmem_t callback,
                                  uint64_t start, uint64_t end, uint32_t pc,
                                  void *user_data);
uc_err add_unmapped_mem_hook(uc_engine *uc);
uc_err add_debug_hooks(uc_engine *uc);
uc_err register_py_handled_mmio_ranges(uc_engine *uc,
                                       uc_cb_hookmem_t py_callback,
                                       uint64_t *starts, uint64_t *ends,
                                       int num_ranges);
uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts,
                                   uint64_t *ends, uint32_t *pcs,
                                   uint32_t *init_vals, uint32_t *steps,
                                   int num_ranges);
uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts,
                                     uint64_t *ends, uint32_t *pcs,
                                     uint32_t *vals, int num_ranges);
uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts,
                                       uint64_t *ends, uint32_t *pcs,
                                       uint8_t *byte_sizes,
                                       uint8_t *left_shifts, uint32_t *masks,
                                       int num_ranges);
uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts,
                                      uint64_t *ends, uint32_t *pcs,
                                      uint32_t *value_nums,
                                      uint32_t **value_lists, int num_ranges);
uc_err set_ignored_mmio_addresses(uint64_t *addresses, uint32_t *pcs,
                                  int num_addresses);
uc_err remove_function_handler_hook_address(uc_engine *uc, uint64_t address);
uc_err register_cond_py_handler_hook(uc_engine *uc,
                                     uc_cb_hookcode_t py_callback,
                                     uint64_t *addrs, int num_addrs,
                                     void *user_data);

uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path);

void initialize_data_tracker_arrays();
int fill_data_tracker_main_dt_array(uint32_t dr, uint32_t callread_pc,
                                    uint32_t read_pc, uint32_t buffer_addr,
                                    uint32_t irq_pc, uint32_t avail_pc,
                                    uint32_t rx_head, uint32_t rx_tail,
                                    short buffer_len, short buffer_min_len,
                                    short consume_count);
int fill_data_tracker_irq_dt_array(uint32_t dr, uint32_t callread_pc,
                                   uint32_t read_pc, uint32_t buffer_addr,
                                   uint32_t irq_pc, uint32_t avail_pc,
                                   uint32_t rx_head, uint32_t rx_tail,
                                   short buffer_len, short buffer_min_len,
                                   short consume_count, uint32_t vtor);
uc_err main_proc_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                                    void *user_data);
uc_err irq_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                              void *user_data);
int ufuzz_adapter_add_avail_hook(uc_engine *uc);
int get_current_partition(DataTracker *dt);
int random_split_data_input(DataTracker *dt);
int random_split_algorithm(int index, int ceil, int threshold);
bool is_head_tail_equal(void *uc, DataTracker *dt);
short uc_mem_read_offset_one_byte(uc_engine *uc, uint64_t addr);
int fill_data(DataTracker *dt, size_t container_len, uc_engine *uc);
int write_byte_to_data_reg(DataTracker *dt, uint8_t *data, int len,
                           uc_engine *uc);
void my_debug_log(const char *format);
int get_match_irq_num(uc_engine *uc, uint32_t irq_pc);
void reset_datatrcker_and_global_vars();
int init_dr_dt_hash();
bool fifo_get_fuzz(uc_engine *uc, DataTracker *dt, uint8_t *buf, uint32_t size);
int stop_for_firmware_read_datareg();

// Ghidra static analysis callback (called from Python via ctypes)
void set_ghidra_callback(void *cb);

// Channel discovery functions
int store_dr_sr_list(uint32_t *dr_addrs, int num_drs,
                     uint32_t *sr_addrs, int num_srs,
                     const char *json_path, uint32_t vtor);
int per_round_reload(uc_engine *uc);
void reset_all_tracker_state(void);
void cleanup_avail_and_pending_hooks(uc_engine *uc);
void rebuild_pending_drs(uc_engine *uc);
void json_reload_dt_arrays(uc_engine *uc);
#endif
