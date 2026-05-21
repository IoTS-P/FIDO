/* Low level unicorn hooks for fuzzing */

/* Porting Considerations
- Memory handlers currently assume shared endianness between host and emulated
target (uc_mem_write)
- ARM thumb instruction set
- System peripherals written for Cortex-M3
*/

#include "native_hooks.h"
#include "core_peripherals/cortexm_nvic.h"
#include "interrupt_triggers.h"
#include "khash.h"
#include "state_snapshotting.h"
#include "timer.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "uc_snapshot.h"
#include "ufuzz_adapter/data_tracker.h"
#include "util.h"
#include <stdbool.h>
#include <sys/types.h>
#include <unicorn/unicorn.h>

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

// 0. Constants
// ~10 MB of preallocated fuzzing buffer size
#define PREALLOCED_FUZZ_BUF_SIZE 10000000
#define MMIO_HOOK_PC_ALL_ACCESS_SITES (0xffffffffuL)
#define DEFAULT_MAX_EXIT_HOOKS 32
#define MMIO_START_UNINIT (0xffffffffffffffffLL)
#define MAX_MMIO_CALLBACKS 4096
#define MAX_IGNORED_ADDRESSES 4096
#define FREAD_NMAX_CHUNKS 5

// AFL-related constants
// 65k bitmap size
#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)
#define FORKSRV_FD 198
#define SHM_ENV_VAR "__AFL_SHM_ID"
// AFL++ compatibility constants
#define SHM_FUZZ_ENV_VAR "__AFL_SHM_FUZZ_ID"
#define FS_OPT_SHDMEM_FUZZ 0x01000000
#define FS_OPT_ENABLED 0x80000001

#define CPUID_ADDR 0xE000ED00
const int CPUID_CORTEX_M4 = 0x410fc240;
const int CPUID_CORTEX_M3 = 0x410fc230;

// static int irq_cnt = 1001;
// static int cnt_group_store = 1001;
// int flag = 0;
// int read_count = 0;
// int avali_count = 0;
// int write_count = 0;
// int tk_interrupt = 0;
// static bool exit_code = false;

uc_err mem_errors[] = {
    UC_ERR_READ_UNMAPPED,  UC_ERR_READ_PROT,  UC_ERR_READ_UNALIGNED,
    UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED,
    UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED,
};

// 1. Static (after initialization) configs
int do_print_exit_info = 0;

uc_hook invalid_mem_hook_handle = 0;
uc_hook hook_block_cond_py_handlers_handle;
uc_cb_hookcode_t py_hle_handler_hook = (uc_cb_hookcode_t)0;
int num_handlers = 0;
uint64_t *bb_handler_locs = 0;
uint32_t fuzz_consumption_timer_id;
uint64_t fuzz_consumption_timeout;
uint32_t instr_limit_timer_id;
void *py_default_mmio_user_data = NULL;
uint32_t num_mmio_regions = 0;
uint64_t *mmio_region_starts = 0;
uint64_t *mmio_region_ends = 0;
int num_mmio_callbacks = 0;
struct mmio_callback *mmio_callbacks[MAX_MMIO_CALLBACKS];
char *input_path = NULL;
uint32_t num_ignored_addresses = 0;
uint64_t ignored_addresses[MAX_IGNORED_ADDRESSES];
uint32_t ignored_address_pcs[MAX_IGNORED_ADDRESSES];
uint32_t exit_at_hit_limit = 1;

uint32_t do_fuzz = 0;

uint64_t instr_limit = 0;

// 2. Transient variables (not required to be included in state restore)
// Housekeeping information for tracing MMIO accesses
unsigned long latest_mmio_fuzz_access_index = 0;
unsigned long latest_mmio_fuzz_access_size = 0;
uint32_t num_exit_hooks = 0;
exit_hook_t exit_hooks[DEFAULT_MAX_EXIT_HOOKS] = {NULL};

uint32_t is_discovery_child = 0;
static int pipe_to_parent[2] = {-1};

uint8_t *fuzz = NULL;
bool input_mode_SHM = false;
long fuzz_size = 0;
long fuzz_cursor = 0;

// 3. Dynamic State (required for state restore)
uint32_t input_already_given = 0;
int duplicate_exit = false;
uc_err custom_exit_reason = UC_ERR_OK;

// Fuzzer coverage bitmap
uint8_t coverage_bitmap[MAP_SIZE];

// 4. DataTracker declarations
#define DATATRACKER_SIZE 100
extern DataTracker *main_dt_array;
extern DataTracker *irq_dt_array;
extern short main_dt_array_index;
extern short irq_dt_array_index;
DataTracker *main_dt_array = NULL;
DataTracker *irq_dt_array = NULL;

short main_dt_array_index = 0;
short irq_dt_array_index = 0;
uint32_t delivery_X = 0;       // X = 全局最小交付块大小
uint32_t delivery_N = 0;       // N = 估算的交付点数量
uint32_t delivery_LenR = 0;    // LenR = 剩余需求预算
int32_t delivery_LenFI = 0;     // LenFI = 剩余额外预算（可为负）
uint32_t global_partion = 0;
uint32_t read_times = 0;
uint32_t vtor_num = 0;
uint32_t stop_count = 1;

bool adapter_can_exit = false;
// 定义哈希表的数据类型
KHASH_MAP_INIT_INT(dr_dt, DataTracker *)
khash_t(dr_dt) *hash_table = NULL;

// Channel discovery globals
DataTracker *pending_dt_array = NULL;
short pending_dt_array_index = 0;

uint32_t g_all_dr_addrs[MAX_DR_ADDRS] = {0};
int g_num_dr_addrs = 0;
uint32_t g_all_sr_addrs[MAX_SR_ADDRS] = {0};
int g_num_sr_addrs = 0;

bool g_in_discovery_mode = false;
uint32_t g_discovery_dr = 0;
uint32_t g_discovery_taint = 0;
uint32_t g_discovery_irq_pc = 0;
uint32_t g_discovery_addr_list[MAX_DISCOVERY_ADDRS] = {0};
int g_discovery_addr_count = 0;
uint32_t g_discovery_buffer_addr = 0;
uc_hook g_discovery_mem_read_hook = 0;
uc_hook g_discovery_mem_write_hook = 0;
bool g_discovery_occurred = false;
char g_json_file_path[512] = {0};

// Phase 0: buffer-addr discovery (taint tracking, no refill)
// After buffer_addr found → parallel fill + read_pc capture:
uint32_t g_discovery_read_pc = 0;
uint32_t g_discovery_callread_pc = 0;
uc_hook g_discovery_buffer_read_hook = 0;
bool g_read_pc_done = false;

// Buffer fill: active chain tracking + manual IRQ
bool g_buffer_fill_active = false;
bool g_buffer_fill_done = false;
uint32_t g_fill_irq_num = 0;        // resolved IRQ number for nvic_set_pending

// Chain tracking (consecutive +1 writes from buffer_addr)
uint32_t g_chain_min = 0;
uint32_t g_chain_max = 0;
int g_chain_extend_count = 0;
int g_consecutive_miss = 0;

// Hard timeout fallback
int g_chain_idle_bb = 0;
uc_hook g_chain_block_hook = 0;

// buffer_min_len inference state machine (semu-fuzz: hook_func_got_buffer_min_len)
static int g_bufmin_state = 0;       // 0=IDLE, 1=INFERRING, 2=DONE
static int g_bufmin_count = 0;
static int g_bufmin_dt_idx = -1;     // which DT is being learned
static uint32_t g_bufmin_irq = 0;
static uc_hook g_bufmin_avail_hook = 0;
static uc_hook g_bufmin_finish_hook = 0;
static uc_hook g_bufmin_read_hook = 0;
static uint32_t g_bufmin_read_off = 0;

// Forward declarations for buffer_min_len hooks
static void hook_bufmin_avail(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_bufmin_finish(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_bufmin_read_ptr(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);

// Ghidra static analysis callback
static void *g_ghidra_callback = NULL;
uc_hook g_avail_hook_handles[MAX_AVAIL_HOOKS] = {0};
int g_num_avail_hooks = 0;
uc_hook g_pending_hook_handles[MAX_PENDING_HOOKS] = {0};
int g_num_pending_hooks = 0;

// 前向声明
void init_delivery_budget(void);
int compute_delivery_size(DataTracker *dt);
bool is_irq_managed_by_dt(int irq_num);
static void finalize_discovery(uc_engine *uc);
static void try_finalize(uc_engine *uc);
void hook_phase1_buffer_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);
static void hook_chain_block(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data);
static bool chain_try_extend(uint32_t addr);

static void determine_input_mode() {
  char *id_str;
  int shm_id;
  int tmp;

  id_str = getenv(SHM_FUZZ_ENV_VAR);
  if (id_str) {
    shm_id = atoi(id_str);
    fuzz = shmat(shm_id, NULL, 0);
    if (!fuzz || fuzz == (void *)-1) {
      perror("[!] could not access fuzzing shared memory");
      exit(1);
    }

    // AFL++ detected. Read its status value
    if (read(FORKSRV_FD, &tmp, 4) != 4) {
      perror("[!] did not receive AFL++ status value");
      exit(1);
    }

    input_mode_SHM = true;
  }
}

void do_exit(uc_engine *uc, uc_err err) {
  printf("[EXIT] cursor=%ld/%ld fuzz_size=%ld read_times=%d\n",
         fuzz_cursor, fuzz_size, fuzz_size, read_times);

  // Clean up discovery hooks if still active
  if (g_in_discovery_mode) {
    if (g_discovery_mem_read_hook) {
      uc_hook_del(uc, g_discovery_mem_read_hook);
      g_discovery_mem_read_hook = 0;
    }
    if (g_discovery_mem_write_hook) {
      uc_hook_del(uc, g_discovery_mem_write_hook);
      g_discovery_mem_write_hook = 0;
    }
    if (g_discovery_buffer_read_hook) {
      uc_hook_del(uc, g_discovery_buffer_read_hook);
      g_discovery_buffer_read_hook = 0;
    }
    if (g_chain_block_hook) {
      uc_hook_del(uc, g_chain_block_hook);
      g_chain_block_hook = 0;
    }
    g_in_discovery_mode = false;
    g_buffer_fill_active = false;
  }

  reset_datatrcker_and_global_vars();
  if (do_print_exit_info) {
    fflush(stdout);
  }
  if (!duplicate_exit) {
    custom_exit_reason = err;
    duplicate_exit = true;
    uc_emu_stop(uc);
  }
}

void hook_block_debug(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint32_t lr;
    uint32_t r0;
    // static int cnt_store = 101;
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    uc_reg_read(uc, UC_ARM_REG_R0, &r0);

    printf("Basic Block: addr= 0x%016lx (lr=0x%x)\n", address, lr);
    printf("$$$r0: (R0=0x%x)\n",r0);

    // if (address == 525764)do_exit(uc, UC_ERR_OK);

    // if (address== 529382){
    //     cnt_group_store--;
    //     // printf("***cnt_store: %d\n",irq_cnt);
    //     printf("***cnt_group_store: %d\n",cnt_group_store);
    //     if (cnt_group_store == 0){
    //       // exit_code = true;
    //       printf("ready to exit\n");
    //       do_exit(uc, UC_ERR_OK);
    //     }
    // }

    // if (address == 529400) {
    //   flag = 1;
    // }

    // if (address == 529462) {
    //   read_count++;
    // }

    // if (address == 529416) {
    //   avali_count++;
    // }

    // if (address == 529528) {
    //   write_count++;
    // }
    // if (address== 528){
    //   do_exit(uc, UC_ERR_OK);
    // }
    fflush(stdout);
}

void hook_debug_mem_access(uc_engine *uc, uc_mem_type type, uint64_t address,
                           int size, int64_t value, void *user_data) {
  uint32_t pc, sp;
  uc_reg_read(uc, UC_ARM_REG_SP, &sp);
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);

  int64_t sp_offset = sp - address;
  if (sp_offset > -0x1000 && sp_offset < 0x2000) {
    if (type == UC_MEM_WRITE) {
      printf("        >>> Write: addr= 0x%08lx[SP:%c%04lx] size=%d "
             "data=0x%08lx (pc 0x%08x)\n",
             address, sp_offset >= 0 ? '+' : '-',
             sp_offset >= 0 ? sp_offset : -sp_offset, size, value, pc);
    } else {
      uint32_t read_value = 0;
      uc_mem_read(uc, address, &read_value, size);
      printf("        >>> Read: addr= 0x%08lx[SP:%c%04lx] size=%d data=0x%08x "
             "(pc 0x%08x)\n",
             address, sp_offset >= 0 ? '+' : '-',
             sp_offset >= 0 ? sp_offset : -sp_offset, size, read_value, pc);
    }
  } else {
    if (type == UC_MEM_WRITE) {
      printf("        >>> Write: addr= 0x%016lx size=%d data=0x%08lx (pc "
             "0x%08x)\n",
             address, size, value, pc);
    } else {
      uint32_t read_value = 0;
      uc_mem_read(uc, address, &read_value, size);
      printf(
          "        >>> Read: addr= 0x%016lx size=%d data=0x%08x (pc 0x%08x)\n",
          address, size, read_value, pc);
    }
  }
  fflush(stdout);
}

uc_err add_debug_hooks(uc_engine *uc) {
  uc_hook tmp;
  uc_err res = UC_ERR_OK;
  // Register unconditional hook for checking for handler presence
  res |= uc_hook_add(uc, &tmp, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_debug,
                     NULL, 1, 0);
  res |= uc_hook_add(uc, &tmp, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ,
                     hook_debug_mem_access, 0, 1, 0);
  return res;
}

bool hook_debug_mem_invalid_access(uc_engine *uc, uc_mem_type type,
                                   uint64_t address, int size, int64_t value,
                                   void *user_data) {
  uint64_t pc = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  if (type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT) {
    printf("        >>> [ 0x%08lx ] INVALID Write: addr= 0x%016lx size=%d "
           "data=0x%016lx\n",
           pc, address, size, value);
  } else if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT) {
    printf("        >>> [ 0x%08lx ] INVALID READ: addr= 0x%016lx size=%d "
           "data=0x%016lx\n",
           pc, address, size, value);
  } else if (type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT) {
    printf("        >>> [ 0x%08lx ] INVALID FETCH: addr= 0x%016lx\n", pc,
           address);
  }
  fflush(stdout);
  return false;
}

int uc_err_to_sig(uc_err error) {
  for (uint32_t i = 0; i < sizeof(mem_errors) / sizeof(*mem_errors); ++i) {
    if (error == mem_errors[i]) {
      return SIGSEGV;
    }
  }
  if (error == UC_ERR_INSN_INVALID) {
    return SIGILL;
  } else {
    return SIGABRT;
  }
}

void force_crash(uc_engine *uc, uc_err error) { printf("there is force crash.\n");do_exit(uc, error); }

void hook_block_exit_at(uc_engine *uc, uint64_t address, uint32_t size,
                        void *user_data) {
  if (++native_hooks_state.curr_exit_at_hit_num == exit_at_hit_limit) {
    if (do_print_exit_info) {
      printf("Hit exit basic block address: %08lx, times: %d\n", address,
             native_hooks_state.curr_exit_at_hit_num);
      fflush(stdout);
    }
    printf("hook_block_exit_at called\n");
    do_exit(uc, UC_ERR_OK);
  }
}

void load_delayed_input(uc_engine *uc) {
  // Having spun up the fork server, we can now load the input file
  if (load_fuzz(input_path) != 0) {
    _exit(-1);
  }

  input_already_given = 1;
}

bool get_fuzz(uc_engine *uc, uint8_t *buf, uint32_t size) {
/*
 * Consuming input is more complex here than one might expect.
 * The reason for this is that we support a prefix input as well
 * as detecting the number of basic blocks that we can execute
 * before consuming fuzzing input.
 *
 * a) The ordinary case is having input, consuming it, and progressing
 * the cursor as one would expect.
 * b) The second case makes the discovery child report the number of
 * translation blocks to run as part of the execution prefix as soon
 * as new fuzzing input would have to be consumed.
 * c) Once after a snapshot, we want to load the fuzzing input. We
 * do this in a delayed manner to support pre-loaded prefix inputs
 * (which are consumed as part of the execution prefix).
 * d) In case we have already loaded the dynamic input once, we
 * finally ran out of input to provide and conclude the run.
 */
#ifdef DEBUG
  printf("[NATIVE FUZZ] Requiring %d fuzz bytes\n", size);
  fflush(stdout);
#endif
// #ifdef MYDEBUG
// char mybuf[100];
// uint32_t myipsr = 0;
// uc_reg_read(uc, UC_ARM_REG_IPSR, &myipsr);
// sprintf(mybuf, "myipsr = %x\n", myipsr);
// my_debug_log(mybuf);
// #endif

  // Deal with copying over the (remaining) fuzzing bytes
  if (size && fuzz_cursor + size <= fuzz_size) {
#ifdef DEBUG
    printf("[NATIVE FUZZ] Returning %d fuzz bytes\n", size);
    fflush(stdout);
#endif
    memcpy(buf, &fuzz[fuzz_cursor], size);
    fuzz_cursor += size;

    // We are consuming fuzzing input, reset watchdog
    reload_timer(fuzz_consumption_timer_id);

    return 0;
  } else if (unlikely(is_discovery_child)) {
    // We are the discovery child, report the current tick count
    uint64_t ticks_so_far = get_global_ticker();
    if (write(pipe_to_parent[1], &ticks_so_far, sizeof(ticks_so_far)) !=
        sizeof(ticks_so_far)) {
      puts(
          "[Discovery Child] Error: could not write number of ticks to parent");
      fflush(stdout);
    }
    _exit(0);
  } else if (!input_already_given) {
    // Load file-based input now
    load_delayed_input(uc);

    return get_fuzz(uc, buf, size);
  } else {
    // 部分耗尽：还有剩余数据但不够请求大小，返回可用的
    if (size && fuzz_cursor < fuzz_size) {
      uint32_t remaining = fuzz_size - fuzz_cursor;
      memcpy(buf, &fuzz[fuzz_cursor], remaining);
      fuzz_cursor += remaining;
      reload_timer(fuzz_consumption_timer_id);
      return 0;
    }
    // 真正耗尽
    if (do_print_exit_info) {
      puts("\n>>> Ran out of fuzz\n");
      do_exit(uc, UC_ERR_OK);
    }
    // printf("get_fuzz called do_exit\n");
    // do_exit(uc, UC_ERR_OK);
    return 1;
  }
}

uint32_t fuzz_consumed() { return fuzz_cursor; }

uint8_t *get_fuzz_ptr(uc_engine *uc, uint32_t size) {
#ifdef DEBUG
  printf("[NATIVE FUZZ] Requiring %d fuzz bytes\n", size);
  fflush(stdout);
#endif

  // Deal with handing out pointer to fuzzing bytes
  if (size && fuzz_cursor + size <= fuzz_size) {
#ifdef DEBUG
    printf("[NATIVE FUZZ] Returning %d fuzz bytes\n", size);
    fflush(stdout);
#endif
    uint8_t *res = &fuzz[fuzz_cursor];
    fuzz_cursor += size;

    // We are consuming fuzzing input, reset watchdog
    reload_timer(fuzz_consumption_timer_id);

    return res;
  } else if (unlikely(is_discovery_child)) {
    // We are the discovery child, report the current tick count
    uint64_t ticks_so_far = get_global_ticker();
    if (write(pipe_to_parent[1], &ticks_so_far, sizeof(ticks_so_far)) !=
        sizeof(ticks_so_far)) {
      puts(
          "[Discovery Child] Error: could not write number of ticks to parent");
      fflush(stdout);
    }
    _exit(0);
  } else if (!input_already_given) {
    // Load file-based input now
    load_delayed_input(uc);

    return get_fuzz_ptr(uc, size);
  } else {
    if (do_print_exit_info) {
      puts("\n>>> Ran out of fuzz\n");
      fflush(stdout);
    }
    my_debug_log("do_exit:ran out of fuzz\n");
    fuzz_cursor = 0;
    if (size && fuzz_cursor + size <= fuzz_size) {
      uint8_t *res = &fuzz[fuzz_cursor];
      fuzz_cursor += size;

      // We are consuming fuzzing input, reset watchdog
      reload_timer(fuzz_consumption_timer_id);

      return res;
    }
    printf("get_fuzz_ptr called do_exit\n");
    do_exit(uc, UC_ERR_OK);
    return NULL;
  }
}

uint32_t get_latest_mmio_fuzz_access_index() {
  return latest_mmio_fuzz_access_index;
}

uint32_t get_latest_mmio_fuzz_access_size() {
  return latest_mmio_fuzz_access_size;
}

uint32_t fuzz_remaining() { return fuzz_size - fuzz_cursor; }

void hook_mmio_access(uc_engine *uc, uc_mem_type type, uint64_t addr, int size,
                      int64_t value, void *user_data) {
  uint32_t pc = 0;
  latest_mmio_fuzz_access_index = fuzz_cursor;

  uc_reg_read(uc, UC_ARM_REG_PC, &pc);

  // TODO: optimize this lookup
  for (int i = 0; i < num_ignored_addresses; ++i) {
    if (addr == ignored_addresses[i] &&
        (ignored_address_pcs[i] == MMIO_HOOK_PC_ALL_ACCESS_SITES ||
         ignored_address_pcs[i] == pc)) {
#ifdef DEBUG
      printf("Hit passthrough address 0x%08lx - pc: 0x%08x - returning\n", addr,
             pc);
      fflush(stdout);
#endif
      goto out;
    }
  }

  for (int i = 0; i < num_mmio_callbacks; ++i) {
    if (addr >= mmio_callbacks[i]->start && addr <= mmio_callbacks[i]->end &&
        (mmio_callbacks[i]->pc == MMIO_HOOK_PC_ALL_ACCESS_SITES ||
         mmio_callbacks[i]->pc == pc)) {
      if (mmio_callbacks[i]->user_data != NULL) {
        user_data = mmio_callbacks[i]->user_data;
      }

      mmio_callbacks[i]->callback(uc, type, addr, size, value, user_data);
      goto out;
    }
  }

#ifdef DEBUG
  printf("Serving %d byte(s) fuzz for mmio access to 0x%08lx, pc: 0x%08x, rem "
         "bytes: %ld\n",
         size, addr, pc, fuzz_size - fuzz_cursor);
  fflush(stdout);
#endif

  uint64_t val = 0;

  // 兜底：DT FIFO 优先，get_fuzz 后备
  if (hash_table != NULL) {
    khint_t k = kh_get(dr_dt, hash_table, addr);
    if (k != kh_end(hash_table)) {
      DataTracker *dt = kh_value(hash_table, k);
      if (!fifo_get_fuzz(uc, dt, (uint8_t *)&val, size)) {
        goto write_val;
      }
    }
  }
  if (get_fuzz(uc, (uint8_t *)&val, size)) {
    return;
  }
write_val:
  uc_mem_write(uc, addr, (uint8_t *)&val, size);

out:

  latest_mmio_fuzz_access_size = fuzz_cursor - latest_mmio_fuzz_access_index;
  return;
}

void add_exit_hook(exit_hook_t hook) {
  if (num_exit_hooks == DEFAULT_MAX_EXIT_HOOKS) {
    perror("ERROR. add_exit_hook: Out of exit hook slots\n");
    exit(-1);
  }
  exit_hooks[num_exit_hooks++] = hook;
}

uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end) {
  if (!py_default_mmio_user_data) {
    perror("ERROR. add_mmio_region: py_default_mmio_user_data is NULL (did you "
           "not register handler first?)\n");
    return UC_ERR_EXCEPTION;
  }

  uc_hook tmp;
  printf("add_mmio_region called! hooking 0x%08lx - 0x%08lx\n", begin, end);
  return uc_hook_add(uc, &tmp, UC_HOOK_MEM_READ, hook_mmio_access,
                     py_default_mmio_user_data, begin, end);
}

void hook_block_cond_py_handlers(uc_engine *uc, uint64_t address, uint32_t size,
                                 void *user_data) {
  uint64_t next_val;

  // Search for address in value list and invoke python handler if found
  for (int i = 0; i < num_handlers; ++i) {
    next_val = bb_handler_locs[i];
    if (next_val > address) {
      break;
    } else if (next_val == address) {
      py_hle_handler_hook(uc, address, size, user_data);
    }
  }
}

uc_err register_cond_py_handler_hook(uc_engine *uc,
                                     uc_cb_hookcode_t py_mmio_callback,
                                     uint64_t *addrs, int num_addrs,
                                     void *user_data) {
  py_hle_handler_hook = py_mmio_callback;
  num_handlers = num_addrs;

  bb_handler_locs = malloc(num_addrs * sizeof(uint64_t));
  if (!bb_handler_locs) {
    perror("allocating handler location struct failed\n");
    return -1;
  }

  memcpy(bb_handler_locs, addrs, num_addrs * sizeof(uint64_t));

  // shouldn't be many entries, just sort ascending this way
  for (int i = 0; i < num_addrs; i++) {
    for (int j = 0; j < num_addrs; j++) {
      if (bb_handler_locs[j] > bb_handler_locs[i]) {
        uint64_t tmp = bb_handler_locs[i];
        bb_handler_locs[i] = bb_handler_locs[j];
        bb_handler_locs[j] = tmp;
      }
    }
  }

  // Register unconditional hook for checking for handler presence
  return uc_hook_add(uc, &hook_block_cond_py_handlers_handle,
                     UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_cond_py_handlers,
                     user_data, 1, 0);
}

uc_err remove_function_handler_hook_address(uc_engine *uc, uint64_t address) {
  for (int i = 0; i < num_handlers; i++) {
    if (bb_handler_locs[i] == address) {
      // Found the handler location, now move everything else to the front
      for (int j = i; j < num_handlers - 1; ++j) {
        bb_handler_locs[j] = bb_handler_locs[j + 1];
      }

      --num_handlers;
      // Now fully remove the (unconditional) hook if we can
      if (!num_handlers) {
        uc_hook_del(uc, hook_block_cond_py_handlers_handle);
      }
      return UC_ERR_OK;
    }
  }

  perror("[NATIVE ERROR] remove_function_handler_hook_address: could not find "
         "address to be removed\n");
  exit(-1);
}

uc_err register_py_handled_mmio_ranges(uc_engine *uc,
                                       uc_cb_hookmem_t py_mmio_callback,
                                       uint64_t *starts, uint64_t *ends,
                                       int num_ranges) {
  uint64_t start, end;

  if (py_default_mmio_user_data == NULL) {
    perror("ERROR. register_py_handled_mmio_ranges: python user data pointer "
           "not set up (did you forget to call init before?)\n");
    return UC_ERR_EXCEPTION;
  }

  for (int i = 0; i < num_ranges; ++i) {
    start = starts[i];
    end = ends[i];
    if (add_mmio_subregion_handler(uc, py_mmio_callback, start, end,
                                   MMIO_HOOK_PC_ALL_ACCESS_SITES,
                                   py_default_mmio_user_data) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

void linear_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr,
                               int size, int64_t value, void *user_data) {
  struct linear_mmio_model_config *model_state =
      (struct linear_mmio_model_config *)user_data;

  model_state->val += model_state->step;

#ifdef DEBUG
  uint32_t pc;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  printf("[0x%08x] Native Linear MMIO handler: [0x%08lx] = [0x%x]\n", pc, addr,
         model_state->val);
  fflush(stdout);
#endif

  uc_mem_write(uc, addr, &model_state->val, sizeof(model_state->val));
}

void constant_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr,
                                 int size, int64_t value, void *user_data) {
  struct constant_mmio_model_config *model_state =
      (struct constant_mmio_model_config *)user_data;
  uint64_t val = model_state->val;

#ifdef DEBUG
  uint32_t pc;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  printf("[0x%08x] Native Constant MMIO handler: [0x%08lx] = [0x%lx]\n", pc,
         addr, val);
  fflush(stdout);
#endif

  // TODO: This assumes shared endianness between host and target
  uc_mem_write(uc, addr, &val, size);
}

void bitextract_mmio_model_handler(uc_engine *uc, uc_mem_type type,
                                   uint64_t addr, int size, int64_t value,
                                   void *user_data) {
  struct bitextract_mmio_model_config *config =
      (struct bitextract_mmio_model_config *)user_data;
  uint64_t result_val = 0;
  uint64_t fuzzer_val = 0;

  // 数据源选择：DT FIFO 优先，get_fuzz 后备
  if (hash_table != NULL) {
    khint_t k = kh_get(dr_dt, hash_table, addr);
    if (k != kh_end(hash_table)) {
      DataTracker *dt = kh_value(hash_table, k);
      if (!fifo_get_fuzz(uc, dt, (uint8_t *)(&fuzzer_val), config->byte_size)) {
        goto apply_model;
      }
    }
  }
  if (get_fuzz(uc, (uint8_t *)(&fuzzer_val), config->byte_size)) {
    return;
  }

apply_model:
  result_val = fuzzer_val << config->left_shift;

#ifdef DEBUG
  uint32_t _pc;
  uc_reg_read(uc, UC_ARM_REG_PC, &_pc);
  printf("[0x%08x] Native Bitextract MMIO handler: [0x%08lx] = [0x%lx] "
         "from %d byte input: %lx\n",
         _pc, addr, result_val, config->byte_size, fuzzer_val);
  fflush(stdout);
#endif

  uc_mem_write(uc, addr, &result_val, size);
}

void value_set_mmio_model_handler(uc_engine *uc, uc_mem_type type,
                                  uint64_t addr, int size, int64_t value,
                                  void *user_data) {
  struct value_set_mmio_model_config *config =
      (struct value_set_mmio_model_config *)user_data;

  uint64_t result_val;
  uint8_t fuzzer_val = 0;
  // #ifdef DEBUG
  uint32_t pc;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  // #endif

  if (config->num_vals > 1) {
    // 数据源选择：DT FIFO 优先，get_fuzz 后备
    if (hash_table != NULL) {
      khint_t k = kh_get(dr_dt, hash_table, addr);
      if (k != kh_end(hash_table)) {
        DataTracker *dt = kh_value(hash_table, k);
        if (!fifo_get_fuzz(uc, dt, (uint8_t *)&fuzzer_val, 1)) {
          goto apply_value_set;
        }
      }
    }
    if (get_fuzz(uc, (uint8_t *)&fuzzer_val, 1)) {
      return;
    }
apply_value_set:
    result_val = config->values[fuzzer_val % config->num_vals];
  } else {
    result_val = config->values[0];
  }

#ifdef DEBUG
  printf("[0x%08x] Native Set MMIO handler: [0x%08lx] = [0x%lx] from input: %x "
         "[values: ",
         pc, addr, result_val, fuzzer_val);
  for (uint32_t i = 0; i < config->num_vals; ++i) {
    if (i) {
      printf(", ");
    }
    printf("%x", config->values[i]);
  }
  printf("]\n");
  fflush(stdout);
#endif
  uc_mem_write(uc, addr, (uint8_t *)&result_val, size);
}

uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts,
                                     uint64_t *ends, uint32_t *pcs,
                                     uint32_t *vals, int num_ranges) {
  struct constant_mmio_model_config *model_configs =
      calloc(num_ranges, sizeof(struct constant_mmio_model_config));

  for (int i = 0; i < num_ranges; ++i) {
#ifdef DEBUG
    printf(
        "Registering constant model for range: [%x] %lx - %lx with val: %x\n",
        pcs[i], starts[i], ends[i], vals[i]);
    fflush(stdout);
#endif

    model_configs[i].val = vals[i];

    if (add_mmio_subregion_handler(uc, constant_mmio_model_handler, starts[i],
                                   ends[i], pcs[i],
                                   &model_configs[i]) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts,
                                   uint64_t *ends, uint32_t *pcs,
                                   uint32_t *init_vals, uint32_t *steps,
                                   int num_ranges) {
  // TODO: support cleanup, currently we just allocate, hand out pointers and
  // forget about them
  struct linear_mmio_model_config *model_configs =
      calloc(num_ranges, sizeof(struct linear_mmio_model_config));

  for (int i = 0; i < num_ranges; ++i) {
#ifdef DEBUG
    printf("Registering linear model for range: [%x] %lx - %lx with step: %x\n",
           pcs[i], starts[i], ends[i], steps[i]);
    fflush(stdout);
#endif
    model_configs[i].val = init_vals[i];
    model_configs[i].step = steps[i];

    if (add_mmio_subregion_handler(uc, linear_mmio_model_handler, starts[i],
                                   ends[i], pcs[i],
                                   &model_configs[i]) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts,
                                       uint64_t *ends, uint32_t *pcs,
                                       uint8_t *byte_sizes,
                                       uint8_t *left_shifts, uint32_t *masks,
                                       int num_ranges) {
  struct bitextract_mmio_model_config *model_configs =
      calloc(num_ranges, sizeof(struct bitextract_mmio_model_config));

  for (int i = 0; i < num_ranges; ++i) {
    model_configs[i].mask = masks[i];
    model_configs[i].byte_size = byte_sizes[i];
    model_configs[i].left_shift = left_shifts[i];
    model_configs[i].mask_hamming_weight = 0;

    uint32_t mask = masks[i];
    while (mask) {
      if (mask & 1) {
        ++model_configs[i].mask_hamming_weight;
      }
      mask >>= 1;
    }

    #ifdef DEBUG
    printf("Registering bitextract model for range: [%x] %lx - %lx with size, "
           "left_shift: %d, %d. Mask: %08x, hw: %d\n",
           pcs[i], starts[i], ends[i], byte_sizes[i], left_shifts[i], masks[i],
           model_configs[i].mask_hamming_weight);
    fflush(stdout);
    #endif

    if (add_mmio_subregion_handler(uc, bitextract_mmio_model_handler, starts[i],
                                   ends[i], pcs[i],
                                   &model_configs[i]) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts,
                                      uint64_t *ends, uint32_t *pcs,
                                      uint32_t *value_nums,
                                      uint32_t **value_lists, int num_ranges) {
  struct value_set_mmio_model_config *model_configs =
      calloc(num_ranges, sizeof(struct value_set_mmio_model_config));

  printf("Registering incoming Value Set models\n");

  for (int i = 0; i < num_ranges; ++i) {
#ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("Registering value set model: [%x] %lx - %lx with numvalues, "
           "value_set: %d, [",
           pcs[i], starts[i], ends[i], value_nums[i]);
    for (uint32_t j = 0; j < value_nums[i]; ++j) {
      if (j) {
        printf(", ");
      }
      printf("%x", value_lists[i][j]);
    }
    printf("]\n");
    fflush(stdout);
#endif

    model_configs[i].num_vals = value_nums[i];
    model_configs[i].values = calloc(value_nums[i], sizeof(**value_lists));
    for (int j = 0; j < value_nums[i]; ++j) {
      model_configs[i].values[j] = value_lists[i][j];
    }

    if (add_mmio_subregion_handler(uc, value_set_mmio_model_handler, starts[i],
                                   ends[i], pcs[i],
                                   &model_configs[i]) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

uc_err set_ignored_mmio_addresses(uint64_t *addresses, uint32_t *pcs,
                                  int num_addresses) {
  assert(sizeof(*addresses) == sizeof(*ignored_addresses));
  assert(sizeof(*pcs) == sizeof(*ignored_address_pcs));

  if (num_addresses <= MAX_IGNORED_ADDRESSES) {
#ifdef DEBUG
    for (int i = 0; i < num_addresses; ++i) {
      printf("Registering passthrough address: [%x] %lx\n", pcs[i],
             addresses[i]);
    }
#endif
    memcpy(ignored_addresses, addresses,
           num_addresses * sizeof(*ignored_addresses));
    memcpy(ignored_address_pcs, pcs,
           num_addresses * sizeof(*ignored_address_pcs));
    num_ignored_addresses = num_addresses;
    return UC_ERR_OK;
  } else {
    printf("Too many ignored addresses to be registered");
    return UC_ERR_EXCEPTION;
  }
}

uc_err load_fuzz(const char *path) {
  FILE *fp;
  long leftover_size;

  if (input_mode_SHM) {
    // shm inputs: <size_u32> contents ...
    fuzz_size = (*(uint32_t *)fuzz) + sizeof(uint32_t);
    fuzz_cursor = sizeof(uint32_t);
    init_delivery_budget();
    return 0;
  }

  leftover_size = fuzz_size - fuzz_cursor;

  if (leftover_size != 0) {
    perror("Got prefix input which is not fully consumed. Exiting...\n");
    exit(-1);
  }

  if (!(fp = fopen(path, "r"))) {
    perror("Opening file failed\n");
    return -1;
  }

  if (fseek(fp, 0L, SEEK_END)) {
    perror("fseek failed\n");
    return -1;
  }

  if ((fuzz_size = ftell(fp)) < 0) {
    perror("ftell failed\n");
    return -1;
  }
  rewind(fp);

#ifdef DEBUG
  printf("leftover_size = %ld, fuzz_size = %ld (path: %s)\n", leftover_size,
         fuzz_size, path);
#endif

  if (fuzz_size > PREALLOCED_FUZZ_BUF_SIZE) {
    // As we may need to copy over leftover contents, keep ref

    if (!(fuzz = calloc(fuzz_size, 1))) {
      perror("Allocating fuzz buffer failed\n");
      return -1;
    }

#ifdef DEBUG
    printf("Allocated new oversized fuzz buffer of size 0x%lx\n", fuzz_size);
#endif
  }

  fuzz_cursor = 0;

  // Give reading the input multiple chunk tries
  size_t num_chunks, already_read = 0, last_read, to_be_read = fuzz_size;
  for (num_chunks = 0; to_be_read && num_chunks < FREAD_NMAX_CHUNKS;
       ++num_chunks) {
    last_read = fread(&fuzz[already_read], 1, to_be_read, fp);
    to_be_read -= last_read;
    already_read += last_read;
  }
  fclose(fp);

  if (to_be_read) {
    perror("fread failed\n");
    return -1;
  }

  init_delivery_budget();
  return 0;
}

static void *init_bitmap(uc_engine *uc) {
  // Use local backup bitmap to run without AFL
  void *bitmap = &coverage_bitmap[0];

  // Indicate to possible afl++ that we can use SHM fuzzing
  uint32_t tmp = FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ;
  char *id_str;
  int shm_id;

  /* Tell AFL once that we are here  */
  id_str = getenv(SHM_ENV_VAR);
  if (id_str) {
    shm_id = atoi(id_str);
    bitmap = shmat(shm_id, NULL, 0);

    if (bitmap == (void *)-1) {
      // We allow this case so we can use the emulator in a forkserver-aware
      // trace gen worker
      puts("[FORKSERVER SETUP] Could not map SHM, reverting to local buffer");
      bitmap = &coverage_bitmap[0];
    }

    if (write(FORKSRV_FD + 1, &tmp, 4) == 4) {
      do_fuzz = 1;
    } else {
      puts("[FORKSERVER SETUP] Got shared memory region, but no pipe. going "
           "for single input");
      do_fuzz = 0;
    }
  } else {
    puts("[FORKSERVER SETUP] It looks like we are not running under AFL, "
         "going "
         "for single input");
    do_fuzz = 0;
  }

  uc_fuzzer_init_cov(uc, bitmap, MAP_SIZE);

  return bitmap;
}

static inline int run_single(uc_engine *uc) {
  int status;
  uint64_t pc = 0;
  int sig = -1;

  uc_reg_read(uc, UC_ARM_REG_PC, &pc);

  status = uc_emu_start(uc, pc | 1, 0, 0, 0);

  if (custom_exit_reason != UC_ERR_OK) {
    status = custom_exit_reason;
  }

  if (status != UC_ERR_OK) {
    if (do_print_exit_info) {
      printf("Execution failed with error code: %d -> %s\n", status,
             uc_strerror(status));
      print_state(uc);
    }
    sig = uc_err_to_sig(status);
  }

  for (uint32_t i = 0; i < num_exit_hooks; ++i) {
    exit_hooks[i](status, sig);
  }

  return sig == -1 ? status : sig;
}

uc_err add_mmio_subregion_handler(uc_engine *uc, uc_cb_hookmem_t callback,
                                  uint64_t start, uint64_t end, uint32_t pc,
                                  void *user_data) {
  if (num_mmio_callbacks >= MAX_MMIO_CALLBACKS) {
    printf("ERROR add_mmio_subregion_handler: Maximum number of mmio callbacks "
           "exceeded\n");
    return -1;
  }

  if (!num_mmio_regions) {
    printf("ERROR add_mmio_subregion_handler: mmio start and end addresses not "
           "configured, yet\n");
    return UC_ERR_EXCEPTION;
  }

  int custom_region = 1;
  for (int i = 0; i < num_mmio_regions; ++i) {
    if (!(start < mmio_region_starts[i] || end > mmio_region_ends[i])) {
      custom_region = 0;
    }
  }

  if (custom_region) {
    printf("Attaching native listener to custom mmio subregion 0x%08lx-0x%08lx",
           start, end);
    add_mmio_region(uc, start, end);
  }

  struct mmio_callback *cb = calloc(1, sizeof(struct mmio_callback));
  cb->callback = callback;
  cb->start = start;
  cb->user_data = user_data;
  cb->end = end;
  cb->pc = pc;

  mmio_callbacks[num_mmio_callbacks++] = cb;

  return UC_ERR_OK;
}

void fuzz_consumption_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
  if (do_print_exit_info) {
    printf("Fuzzing input not consumed for %ld basic blocks, exiting\n",
           fuzz_consumption_timeout);
  }
  printf("fuzz_consumption_timeout_cb called, do_exit\n");
  do_exit(uc, UC_ERR_OK);
}

#ifdef DEBUG_INJECT_TIMER
void test_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
  if (!is_discovery_child) {
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    fflush(NULL);
  }
}
#endif

void instr_limit_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
  if (do_print_exit_info) {
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("Ran into instruction limit of %lu at 0x%08x - exiting\n",
           get_timer_reload_val(instr_limit_timer_id), pc);
  }
  printf("instr_limit_timeout_cb called, do_exit\n");
  do_exit(uc, UC_ERR_OK);
}

void *mmio_models_take_snapshot(uc_engine *uc) {
  size_t size = num_ignored_addresses * sizeof(uint32_t);
  uint32_t *passthrough_init_vals = malloc(size);

  for (int i = 0; i < num_ignored_addresses; ++i) {
    uc_mem_read(uc, ignored_addresses[i], &passthrough_init_vals[i],
                sizeof(*passthrough_init_vals));
  }

  return passthrough_init_vals;
}

void mmio_models_restore_snapshot(uc_engine *uc, void *snapshot) {
  uint32_t *passthrough_init_vals = (uint32_t *)snapshot;

  // Restore the initial passthrough MMIO values
  for (int i = 0; i < num_ignored_addresses; ++i) {
    uc_mem_write(uc, ignored_addresses[i], &passthrough_init_vals[i],
                 sizeof(*passthrough_init_vals));
  }
}

void mmio_models_discard_snapshot(uc_engine *uc, void *snapshot) {
  free(snapshot);
}

uc_err init(uc_engine *uc, exit_hook_t p_exit_hook, int p_num_mmio_regions,
            uint64_t *p_mmio_starts, uint64_t *p_mmio_ends,
            void *p_py_default_mmio_user_data, uint32_t num_exit_at_bbls,
            uint64_t *exit_at_bbls, uint32_t p_exit_at_hit_limit,
            int p_do_print_exit_info, uint64_t p_fuzz_consumption_timeout,
            uint64_t p_instr_limit) {
  // TODO: assumes shared endianness
  uc_mem_write(uc, CPUID_ADDR, &CPUID_CORTEX_M4, sizeof(CPUID_CORTEX_M4));

  if (p_exit_hook) {
    add_exit_hook(p_exit_hook);
  }

  exit_at_hit_limit = p_exit_at_hit_limit;
  do_print_exit_info = p_do_print_exit_info;

  if (do_print_exit_info) {
    uc_hook_add(uc, &invalid_mem_hook_handle,
                UC_HOOK_MEM_WRITE_INVALID | UC_HOOK_MEM_READ_INVALID |
                    UC_HOOK_MEM_FETCH_INVALID,
                hook_debug_mem_invalid_access, 0, 1, 0);
  }

  // Add fuzz consumption timeout as timer
  fuzz_consumption_timeout = p_fuzz_consumption_timeout;
  fuzz_consumption_timer_id =
      add_timer(fuzz_consumption_timeout, fuzz_consumption_timeout_cb, NULL,
                TIMER_IRQ_NOT_USED);
  if (fuzz_consumption_timeout) {
    start_timer(uc, fuzz_consumption_timer_id);
  }

#ifdef DEBUG_INJECT_TIMER
  // debug timer to debug precise timing consistencies
  start_timer(uc, add_timer(DEBUG_TIMER_TIMEOUT, test_timeout_cb, NULL,
                            TIMER_IRQ_NOT_USED));
#endif

  instr_limit = p_instr_limit;
  instr_limit_timer_id =
      add_timer(instr_limit, instr_limit_timeout_cb, NULL, TIMER_IRQ_NOT_USED);
  if (instr_limit) {
    start_timer(uc, instr_limit_timer_id);
  }

  py_default_mmio_user_data = p_py_default_mmio_user_data;

  for (uint32_t i = 0; i < num_exit_at_bbls; ++i) {
    uint64_t tmp;
    uint64_t bbl_addr = exit_at_bbls[i] & (~1LL);
    if (uc_hook_add(uc, &tmp, UC_HOOK_BLOCK, hook_block_exit_at, 0, bbl_addr,
                    bbl_addr) != UC_ERR_OK) {
      perror("Could not register exit-at block hook...\n");
      return -1;
    }
  }

  if (!(fuzz = calloc(PREALLOCED_FUZZ_BUF_SIZE, 1))) {
    perror("Allocating fuzz buffer failed\n");
    return -1;
  }

  // Register read hooks for mmio regions
  num_mmio_regions = p_num_mmio_regions;
  mmio_region_starts = calloc(num_mmio_regions, sizeof(*p_mmio_starts));
  mmio_region_ends = calloc(num_mmio_regions, sizeof(*p_mmio_ends));
  memcpy(mmio_region_starts, p_mmio_starts,
         num_mmio_regions * sizeof(*p_mmio_starts));
  memcpy(mmio_region_ends, p_mmio_ends,
         num_mmio_regions * sizeof(*p_mmio_ends));

  for (int i = 0; i < num_mmio_regions; ++i) {
    if (add_mmio_region(uc, mmio_region_starts[i], mmio_region_ends[i]) !=
        UC_ERR_OK) {
      perror("[native init] could not register mmio region.\n");
      return UC_ERR_EXCEPTION;
    }
  }

  // Snapshotting
  init_interrupt_triggering(uc);

  init_uc_state_snapshotting(uc);

  subscribe_state_snapshotting(uc, mmio_models_take_snapshot,
                               mmio_models_restore_snapshot,
                               mmio_models_discard_snapshot);

  initialize_data_tracker_arrays();
  return UC_ERR_OK;
}

static void restore_snapshot(uc_engine *uc) {
  // Restore all subscribed snapshot parts
  trigger_restore(uc);

  // Also reset fuzzing input cursor and exit detection
  fuzz_cursor = fuzz_size;
  input_already_given = 0;
  duplicate_exit = false;
  custom_exit_reason = UC_ERR_OK;
}

uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path) {
  uint64_t pc = 0;
  fflush(stdout);

  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  init_bitmap(uc);

  /*
   * Pre-execute deterministic part of target execution (the execution prefix)
   * Anything before consuming dynamic fuzzing input for the first time is
   * deterministic. This includes a potential prefix input which we will also
   * consume during this stage to effectively restore a snapshot (which the
   * prefix input leads us to).
   */

  // Set input path for the fuzz reading handler to pick up on later
  input_path = p_input_path;
  // Pre-load prefix input
  if (prefix_input_path) {
    if (load_fuzz(prefix_input_path) != 0) {
      _exit(-1);
    }
  }

  /*
   * This part of executing the execution prefix is a bit tricky:
   * We cannot simply run up to the first MMIO access, as this will leave our
   * execution context in the middle of an MMIO access, which would leave
   * unicorn in a state which we cannot snapshot. So instead, we fork and
   * discover how much execution we have ahead of us before running into the
   * first fuzzing input-consuming MMIO access. We report this number from the
   * forked child to the parent via a pipe.
   */
  pid_t child_pid;
  uint64_t required_ticks = -1;
  if (pipe(pipe_to_parent)) {
    puts("[ERROR] Could not create pipe for discovery forking");
    exit(-1);
  }

  // For every run (and to keep consistency between single and fuzzing runs),
  // find out how many basic blocks we can execute before hitting the first
  // MMIO read
  child_pid = fork();
  if (child_pid) {
    // parent: wait for the discovery child to report back the number of tbs
    // we need to execute
    if (read(pipe_to_parent[0], &required_ticks, sizeof(required_ticks)) !=
        sizeof(required_ticks)) {
      puts("[ERROR] Could not retrieve the number of required ticks during "
           "discovery forking");
      exit(-1);
    }
    waitpid(child_pid, &child_pid, 0);

    close(pipe_to_parent[0]);
    close(pipe_to_parent[1]);

    printf("[DISCOVERY FORK PARENT] Got number of ticks to step: %ld\n",
           required_ticks);

    if (required_ticks > 2) {
      // Set up a timer that will make use stop after executing the prefix
      set_timer_reload_val(instr_limit_timer_id, required_ticks - 2);

      // Execute the prefix
      if (uc_emu_start(uc, pc | 1, 0, 0, 0)) {
        puts("[ERROR] Could not execute the first some steps");
        exit(-1);
      }
    }
    puts("[+] Initial constant execution (including optional prefix input) "
         "done, starting input execution.");
    fflush(stdout);
  } else {
    // child: Run until we hit an input consumption
    is_discovery_child = 1;
    uc_err child_emu_status = uc_emu_start(uc, pc | 1, 0, 0, 0);

    // We do not expect to get here. The child should exit by itself in
    // get_fuzz
    printf("[ERROR] Emulation stopped using just the prefix input (%d: %s)\n",
           child_emu_status, uc_strerror(child_emu_status));

    // Write wrong amount of data to notify parent of failure
    if (write(pipe_to_parent[1], emulate, 1) != 1) {
      puts("[Discovery Child] Error: Could not notify parent of failure...");
      fflush(stdout);
    }
    _exit(-1);
  }

  // After consuming first part of input and executing the prefix, set input
  // mode
  determine_input_mode();
  // Set the proper instruction limit (after using a fake one to execute exec
  // prefix)
  set_timer_reload_val(instr_limit_timer_id, instr_limit);

  // Upon exiting emulation, Unicorn will trigger basic block hits.
  // This ticks off timers two times. This is an issue because this
  // makes timings slightly differ when splitting an input to an input prefix
  // and the remaining input file. Adjust for this offset here.
  // TODO: adjusting the timer has to be done when it is caused.
  // TODO: This seems to be the case when unicorn is stopped, but need to
  // re-visit adjust_timers_for_unicorn_exit();

  if (do_fuzz) {
    uc_fuzzer_reset_cov(uc, 1);
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    trigger_snapshotting(uc);

    // Initial per-round setup: read JSON, build DT arrays, hooks, and pending DRs
    per_round_reload(uc);

    // AFL-compatible Forkserver loop
    child_pid = getpid();
    int count = 0;
    int tmp = 0;
    int sig;
    input_already_given = 0;
    duplicate_exit = false;
    for (;;) {
      ++count;

      /* Wait until we are allowed to run  */
      if (read(FORKSRV_FD, &tmp, 4) != 4) {
        if (count == 1) {
          puts("[FORKSERVER MAIN LOOP] ERROR: Read from FORKSRV_FD to start "
               "new execution failed. Exiting");
          exit(-1);
        } else {
          puts("[FORKSERVER MAIN LOOP] Forkserver pipe now closed. Exiting");
          exit(0);
        }
      }

      uc_fuzzer_reset_cov(uc, 0);

      /* Send AFL the child pid thus it can kill it on timeout   */
      if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
        printf("[FORKSERVER MAIN LOOP] ERROR: Write to FORKSRV_FD+1 to send "
               "fake "
               "child PID failed. errno: %d. Description: '%s'. Count: %d\n",
               errno, strerror(errno), count);
        fflush(stdout);
        exit(-1);
      }

      sig = run_single(uc);

      if (write(FORKSRV_FD + 1, &sig, 4) != 4) {
        puts("[MAIN LOOP] Write to FORKSRV_FD+1 to send status failed");
        _exit(-1);
      }

      restore_snapshot(uc);

      // Ghidra daemon may have patched JSON → trigger reload
      {
        struct stat st;
        if (stat("/tmp/ghidra_done", &st) == 0) {
          unlink("/tmp/ghidra_done");
          g_discovery_occurred = true;
        }
      }

      // Channel discovery: if a new DT was discovered this round, reload config
      if (g_discovery_occurred) {
        per_round_reload(uc);
        g_discovery_occurred = false;
      }
    }
  } else {
    puts("Running without a fork server");
    duplicate_exit = false;

    // Initial per-round setup for single-run mode
    per_round_reload(uc);

    // Not running under fork server
    int sig = run_single(uc);

    if (do_print_exit_info) {
      if (sig) {
        // Crash occurred
        printf("Emulation crashed with signal %d\n", sig);
      } else {
        // Non-crashing exit (includes different timeouts)
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("Exited without crash at 0x%08x - If no other reason, we ran "
               "into one of the limits\n",
               pc);
      }
    }
  }

  return UC_ERR_OK;
}

void initialize_data_tracker_arrays() {
  printf("Initializing data tracker arrays\n");
  main_dt_array = malloc(DATATRACKER_SIZE * sizeof(DataTracker));
  irq_dt_array = malloc(DATATRACKER_SIZE * sizeof(DataTracker));
  pending_dt_array = malloc(MAX_PENDING_DRS * sizeof(DataTracker));
  // Check for NULL if allocation fails and handle it appropriately
  if (!main_dt_array || !irq_dt_array || !pending_dt_array) {
    // Handle memory allocation error
    // For example, you could print an error message and exit
    fprintf(stderr, "Failed to allocate memory for data tracker arrays\n");
    exit(EXIT_FAILURE);
  }
  memset(main_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(irq_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(pending_dt_array, 0, MAX_PENDING_DRS * sizeof(DataTracker));
  printf("Data tracker arrays initialized\n");
}

int fill_data_tracker_main_dt_array(uint32_t dr, uint32_t callread_pc,
                                    uint32_t read_pc, uint32_t buffer_addr,
                                    uint32_t irq_pc, uint32_t avail_pc,
                                    uint32_t rx_head, uint32_t rx_tail,
                                    short buffer_len, short buffer_min_len,
                                    short consume_count) {

  main_dt_array[main_dt_array_index].dr = dr;
  main_dt_array[main_dt_array_index].callread_pc = callread_pc;
  main_dt_array[main_dt_array_index].read_pc = read_pc;
  main_dt_array[main_dt_array_index].buffer_addr = buffer_addr;
  main_dt_array[main_dt_array_index].irq_pc = irq_pc;
  main_dt_array[main_dt_array_index].avail_pc = avail_pc;
  main_dt_array[main_dt_array_index].rx_head = rx_head;
  main_dt_array[main_dt_array_index].rx_tail = rx_tail;
  main_dt_array[main_dt_array_index].buffer_len = buffer_len;
  main_dt_array[main_dt_array_index].buffer_min_len = buffer_min_len;
  main_dt_array[main_dt_array_index].irq_num = 0;
  main_dt_array[main_dt_array_index].fifo_head = 0;
  main_dt_array[main_dt_array_index].fifo_tail = 0;
  if (hash_table == NULL) {
    init_dr_dt_hash();
  }
  // 插入元素
  int ret = 0;
  khint_t k = kh_put(dr_dt, hash_table, dr, &ret); // 插入键
  if (ret != -1) { // 如果 ret 不是 -1，说明插入成功
    kh_value(hash_table, k) =
        &main_dt_array[main_dt_array_index]; // 设置键对应的值
  }
  main_dt_array_index++;
  return 0;
}

int fill_data_tracker_irq_dt_array(uint32_t dr, uint32_t callread_pc,
                                   uint32_t read_pc, uint32_t buffer_addr,
                                   uint32_t irq_pc, uint32_t avail_pc,
                                   uint32_t rx_head, uint32_t rx_tail,
                                   short buffer_len, short buffer_min_len,
                                   short consume_count, uint32_t vtor) {

  irq_dt_array[irq_dt_array_index].dr = dr;
  irq_dt_array[irq_dt_array_index].callread_pc = callread_pc;
  irq_dt_array[irq_dt_array_index].read_pc = read_pc;
  irq_dt_array[irq_dt_array_index].buffer_addr = buffer_addr;
  irq_dt_array[irq_dt_array_index].irq_pc = irq_pc;
  irq_dt_array[irq_dt_array_index].avail_pc = avail_pc;
  irq_dt_array[irq_dt_array_index].rx_head = rx_head;
  irq_dt_array[irq_dt_array_index].rx_tail = rx_tail;
  irq_dt_array[irq_dt_array_index].buffer_len = buffer_len;
  irq_dt_array[irq_dt_array_index].buffer_min_len = buffer_min_len;
  irq_dt_array[irq_dt_array_index].irq_num = 0;
  irq_dt_array[irq_dt_array_index].fifo_head = 0;
  irq_dt_array[irq_dt_array_index].fifo_tail = 0;
  irq_dt_array[irq_dt_array_index].interrupt_times = 0;
  vtor_num = vtor;
  if (hash_table == NULL) {
    init_dr_dt_hash();
  }
  // 插入元素
  int ret = 0;
  khint_t k = kh_put(dr_dt, hash_table, dr, &ret); // 插入键
  if (ret != -1) { // 如果 ret 不是 -1，说明插入成功
    kh_value(hash_table, k) =
        &irq_dt_array[irq_dt_array_index]; // 设置键对应的值
  }
  irq_dt_array_index++;
  return 0;
}

int ufuzz_adapter_add_avail_hook(uc_engine *uc) {
  g_num_avail_hooks = 0;
  for (int i = 0; i < main_dt_array_index; i++) {
    if (main_dt_array[i].avail_pc != 0) {
      uc_hook avail_hook;
      if (uc_hook_add(uc, &avail_hook, UC_HOOK_CODE,
                      main_proc_avail_hook_handler, &main_dt_array[i],
                      main_dt_array[i].avail_pc,
                      main_dt_array[i].avail_pc) != UC_ERR_OK) {
        perror("Could not add avail hook\n");
        return -1;
      }
      if (g_num_avail_hooks < MAX_AVAIL_HOOKS) {
        g_avail_hook_handles[g_num_avail_hooks++] = avail_hook;
      }
    }
  }
  for (int i = 0; i < irq_dt_array_index; i++) {
    if (irq_dt_array[i].avail_pc != 0) {
      uc_hook irq_hook;
      printf("avail_pc = %x\n", irq_dt_array[i].avail_pc);
      FILE *fp = fopen("/tmp/ghidra_reload.log", "a");
      if (fp) { fprintf(fp, "avail_pc=0x%x\n", irq_dt_array[i].avail_pc); fclose(fp); }
      int res = uc_hook_add(uc, &irq_hook, UC_HOOK_CODE, irq_avail_hook_handler,
                            &irq_dt_array[i], irq_dt_array[i].avail_pc,
                            irq_dt_array[i].avail_pc);
      if (res != UC_ERR_OK) {
        perror("Could not add avail hook\n");
        return -1;
      }
      if (g_num_avail_hooks < MAX_AVAIL_HOOKS) {
        g_avail_hook_handles[g_num_avail_hooks++] = irq_hook;
      }
    }
  }

  return 0;
}

uc_err main_proc_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                                    void *user_data) {
  read_times++;
  DataTracker *dt = (DataTracker *)user_data;

  // 主逻辑读：FIFO 空则装填，无中断触发
  if (dt->fifo_head == dt->fifo_tail) {
    int len_si = compute_delivery_size(dt);
    if (len_si == 0) {
      printf("***main dt budget exhausted\n");
      return UC_ERR_OK;
    }
    fill_data(dt, len_si, uc);
    delivery_LenFI = delivery_LenFI - len_si + delivery_X;
    if (delivery_LenFI < 0) delivery_LenFI = 0;
    delivery_LenR  = delivery_LenR - delivery_X;
    if (delivery_LenR == 0) delivery_X = 0;
    printf("***main fill fifo: %d bytes, LenFI=%d, LenR=%d\n",
           len_si, delivery_LenFI, delivery_LenR);
  }
  return UC_ERR_OK;
}

uc_err irq_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                              void *user_data) {
  my_debug_log("irq_avail_hook_handler\n");
  DataTracker *dt = (DataTracker *)user_data;

  // ---- 解析 IRQ 号 ----
  if (dt->irq_pc < 256) {
    dt->irq_num = dt->irq_pc;
  } else if (dt->irq_pc == 256) {
    return UC_ERR_OK;
  } else {
    // 每次重新查询，避免 NVIC 未启用时缓存 0
    dt->irq_num = get_match_irq_num(uc, dt->irq_pc);
    if (dt->irq_num == 0) {
      return UC_ERR_OK;  // 中断尚未启用，等下次
    }
  }

  // ---- FIFO 空则装填 ----
  if (!dt->interrupt_times) {
    int len_si = compute_delivery_size(dt);
    if (len_si == 0) {
      printf("***irq dt budget exhausted\n");
      return UC_ERR_OK;
    }
    fill_data(dt, len_si, uc);
    delivery_LenFI = delivery_LenFI - len_si + delivery_X;
    if (delivery_LenFI < 0) delivery_LenFI = 0;
    delivery_LenR  = delivery_LenR - delivery_X;
    if (delivery_LenR == 0) delivery_X = 0;
    printf("***fill fifo: %d bytes, LenFI=%d, LenR=%d\n",
           len_si, delivery_LenFI, delivery_LenR);
    dt->interrupt_times = len_si;
    return UC_ERR_OK;
  }

  // ---- 触发中断 ----
  nvic_set_pending(uc, dt->irq_num, false);
  dt->interrupt_times--;
  return UC_ERR_OK;
}

// ====== 替换 get_current_partition/random_split 系列函数 ======

// 初始化交付预算（伪代码行 1-13）：估算 N、X、LenR
void init_delivery_budget(void) {
  delivery_N = main_dt_array_index + irq_dt_array_index;
  if (delivery_N == 0) {
    delivery_X = 1;
    delivery_LenR = 0;
    return;
  }
  delivery_X = 0xFFFFFFFF;
  for (int i = 0; i < main_dt_array_index; i++) {
    uint32_t low = main_dt_array[i].buffer_min_len > 0
                       ? main_dt_array[i].buffer_min_len : 1;
    if (low < delivery_X) delivery_X = low;
  }
  for (int i = 0; i < irq_dt_array_index; i++) {
    uint32_t low = irq_dt_array[i].buffer_min_len > 0
                       ? irq_dt_array[i].buffer_min_len : 1;
    if (low < delivery_X) delivery_X = low;
  }
  if (delivery_X == 0xFFFFFFFF || delivery_X == 0) delivery_X = 1;
  delivery_LenR = delivery_N * delivery_X;
  while (fuzz_size < delivery_LenR && delivery_N > 1) {
    delivery_N--;
    delivery_LenR = delivery_N * delivery_X;
  }
  delivery_LenFI = fuzz_size - delivery_LenR;
  printf("[INIT_BUDGET] N=%d X=%d LenR=%d LenFI=%d fuzz_size=%ld\n",
         delivery_N, delivery_X, delivery_LenR, delivery_LenFI, fuzz_size);
}

// 计算本次投递长度 LenSI（伪代码行 17-26）
int compute_delivery_size(DataTracker *dt) {
  int32_t len_fi = delivery_LenFI;                                    // LenFI
  uint32_t X      = delivery_X > 0 ? delivery_X : 1;
  uint32_t low_p  = dt->buffer_min_len > 0 ? dt->buffer_min_len : 1; // LOWp
  if (low_p > 1 && low_p < 4) low_p = 4;  // 原版阈值 clamp
  uint32_t up_p   = dt->buffer_len;                                   // UPp

  // 伪代码行 14
  if (len_fi + delivery_LenR == 0) return 0;
  if (up_p == low_p) return up_p;

  // 伪代码行 17: Δ = LenFI + X - LOWp
  int delta = (int)(len_fi + X) - (int)low_p;
  int len_si;
  if (delta <= 0) {
    // 伪代码行 18-20: LenSI = LOWp, 补零 |Δ| 字节
    len_si = (int)low_p;
    printf("[DELIVERY] Δ=%d≤0 → LenSI=LOWp=%d (LenFI=%d X=%d LOWp=%d)\n",
           delta, len_si, len_fi, X, low_p);
  } else {
    // 伪代码行 23-24: LenSI = Rand(FI[Pos]) mod t + LOWp
    uint32_t upper = (len_fi + X < up_p) ? (len_fi + X) : up_p;
    int t = (int)upper - (int)low_p;
    uint32_t seed = (fuzz_cursor < fuzz_size) ? fuzz[fuzz_cursor] : 0;
    len_si = (seed % t) + low_p;
    printf("[DELIVERY] Δ=%d>0 → LenSI=%d range=[%d,%d] seed=fuzz[%ld]=%u "
           "(LenFI=%d X=%d UPp=%d)\n",
           delta, len_si, low_p, upper, fuzz_cursor, seed,
           len_fi, X, up_p);
  }
  return len_si;
}

// 检查某个 IRQ 是否正被任意 DataTracker 管理
bool is_irq_managed_by_dt(int irq_num) {
  for (int i = 0; i < irq_dt_array_index; i++) {
    if (irq_dt_array[i].irq_num == irq_num)
      return true;
  }
  return false;
}

// ====== 替换结束 ======

// 用于检测是否存在头尾指针并且判断是否相等
bool is_head_tail_equal(void *uc, DataTracker *dt) {
  if (dt->rx_head == 0 || dt->rx_tail == 0) {
    return false;
  }
  short head_byte;
  short tail_byte;

  head_byte = uc_mem_read_offset_one_byte(uc, dt->rx_head);
  tail_byte = uc_mem_read_offset_one_byte(uc, dt->rx_tail);
  if (head_byte != 0 || tail_byte != 0) {
    char buf[100];
    sprintf(buf, "head_byte = %d, tail_byte = %d\n", head_byte, tail_byte);
    my_debug_log(buf);
  }
  int head_offset = head_byte % dt->buffer_len;
  int tail_offset = tail_byte % dt->buffer_len;

  return head_offset == tail_offset;
}

short uc_mem_read_offset_one_byte(uc_engine *uc, uint64_t addr) {
  short offset; // To store the byte read from memory
  uc_err err;
  err = uc_mem_read(uc, addr, &offset, sizeof(offset));
  if (err) {
    fprintf(stderr, "Failed to read memory at address 0x%" PRIx64 "\n", addr);
    return -1;
  }
  return offset;
}

// Function to fill data from fuzz input into DataTracker's FIFO
// Fills exactly container_len bytes, zero-padding if fuzz is exhausted
int fill_data(DataTracker *dt, size_t container_len, uc_engine *uc) {
  size_t remain = (fuzz_size > fuzz_cursor) ? (fuzz_size - fuzz_cursor) : 0;

  if (remain <= 0) {
    printf("fill data called\n");
    // do_exit(uc, UC_ERR_OK);
    return 0;
  }

  int actual_len = (remain < container_len) ? (int)remain : (int)container_len;
  int padding    = (int)container_len - actual_len;

  printf("[FILL] dt→fifo[%d]B: actual=%dB from fuzz[%ld], pad=%dB, "
         "cursor %ld→%ld\n",
         (int)container_len, actual_len, fuzz_cursor, padding,
         fuzz_cursor, fuzz_cursor + actual_len);

  uint8_t data_input[container_len];
  memset(data_input, 0, container_len);

  if (actual_len > 0) {
    memcpy(data_input, fuzz + fuzz_cursor, actual_len);
    fuzz_cursor += actual_len;
  }

  int write_len = write_byte_to_data_reg(dt, data_input, container_len, uc);
  global_partion += write_len;
  return write_len;
}

int write_byte_to_data_reg(DataTracker *dt, uint8_t *data, int len,
                           uc_engine *uc) {
  memcpy(dt->fifo, data, len);                                                                                                                                                                                
  dt->fifo_head = len;    // 修复：应该是 len 而非 len-1                                   
  dt->fifo_tail = 0;                                                                                                                                                                                          
  return len;     
}

void my_debug_log(const char *format) {
#ifdef MYDEBUG
  FILE *debugFile;

  // 打开文件，如果文件不存在则创建，如果存在则追加写入
  debugFile = fopen("/tmp/debug.txt", "a");

  if (debugFile == NULL) {
    fprintf(stderr, "无法打开文件\n");
  }

  // 写入调试信息到文件
  fprintf(debugFile, "%s", format);

  // 关闭文件
  fclose(debugFile);
#endif
  return;
}

int get_match_irq_num(uc_engine *uc, uint32_t irq_pc) {
  int num_enabled = get_num_enabled();
  int irq_num = 0;
  int best_irq = 0;
  int best_diff = 0x7FFFFFFF;
  // printf("[GET_IRQ] irq_pc=0x%x vtor=0x%x enabled=%d\n",
  //        irq_pc, vtor_num, num_enabled);
  for (int i = 1; i <= num_enabled; i++) {
    irq_num = nth_enabled_irq_num(i);
    uint64_t handler_addr = vtor_num + irq_num * 4;
    int handler_val;
    uc_mem_read(uc, handler_addr, &handler_val, sizeof(handler_val));
    int diff = abs((int)(handler_val - (int)irq_pc));
    // printf("[GET_IRQ]   i=%d irq=%d handler=0x%x diff=%d\n",
    //        i, irq_num, handler_val, diff);
    if (diff <= 4) {
      // printf("[GET_IRQ] MATCH irq=%d\n", irq_num);
      return irq_num;
    }
    if (diff < best_diff) {
      best_diff = diff;
      best_irq = irq_num;
    }
  }
  // printf("[GET_IRQ] no exact match, best irq=%d diff=%d\n", best_irq, best_diff);
  return 0;
}

void reset_datatrcker_and_global_vars() {
  global_partion = 0;
  read_times = 0;
  delivery_LenFI = 0;
  for (int i = 0; i < main_dt_array_index; i++) {
    main_dt_array[i].fifo_head = 0;
    main_dt_array[i].fifo_tail = 0;
  }
  for (int i = 0; i < irq_dt_array_index; i++) {
    irq_dt_array[i].fifo_head = 0;
    irq_dt_array[i].fifo_tail = 0;
    irq_dt_array[i].interrupt_times = 0;
  }
  // Refill pending DT FIFOs each round (snapshot restore doesn't touch C heap)
  for (int i = 0; i < pending_dt_array_index; i++) {
    memset(pending_dt_array[i].fifo, 0xAA, 1);
    pending_dt_array[i].fifo_head = 1;
    pending_dt_array[i].fifo_tail = 0;
  }
}

int init_dr_dt_hash() {

  // 创建哈希表
  khash_t(dr_dt) *h = kh_init(dr_dt);
  hash_table = h;
  return 0;

  // 销毁哈希表
  // kh_destroy(dr_dt, h);
}

// ====== Channel Discovery: Init-time Setup ======
int store_dr_sr_list(uint32_t *dr_addrs, int num_drs,
                     uint32_t *sr_addrs, int num_srs,
                     const char *json_path, uint32_t vtor) {
  vtor_num = vtor;
  g_num_dr_addrs = (num_drs < MAX_DR_ADDRS) ? num_drs : MAX_DR_ADDRS;
  memcpy(g_all_dr_addrs, dr_addrs, g_num_dr_addrs * sizeof(uint32_t));
  g_num_sr_addrs = (num_srs < MAX_SR_ADDRS) ? num_srs : MAX_SR_ADDRS;
  memcpy(g_all_sr_addrs, sr_addrs, g_num_sr_addrs * sizeof(uint32_t));
  if (json_path && json_path[0]) {
    strncpy(g_json_file_path, json_path, sizeof(g_json_file_path) - 1);
  }

  if (!pending_dt_array) {
    pending_dt_array = calloc(MAX_PENDING_DRS, sizeof(DataTracker));
  }

  printf("[STORE_DR_SR] stored %d DRs, %d SRs, json=%s, vtor=0x%x\n",
         g_num_dr_addrs, g_num_sr_addrs, g_json_file_path, vtor_num);
  return 0;
}

// ====== Channel Discovery: Per-round Hook Management ======

// Cleanup all avail and pending hooks from previous round
void cleanup_avail_and_pending_hooks(uc_engine *uc) {
  for (int i = 0; i < g_num_avail_hooks; i++) {
    if (g_avail_hook_handles[i]) {
      uc_hook_del(uc, g_avail_hook_handles[i]);
      g_avail_hook_handles[i] = 0;
    }
  }
  g_num_avail_hooks = 0;

  for (int i = 0; i < g_num_pending_hooks; i++) {
    if (g_pending_hook_handles[i]) {
      uc_hook_del(uc, g_pending_hook_handles[i]);
      g_pending_hook_handles[i] = 0;
    }
  }
  g_num_pending_hooks = 0;

  // Clean up any lingering discovery hooks
  if (g_discovery_mem_read_hook) {
    uc_hook_del(uc, g_discovery_mem_read_hook);
    g_discovery_mem_read_hook = 0;
  }
  if (g_discovery_mem_write_hook) {
    uc_hook_del(uc, g_discovery_mem_write_hook);
    g_discovery_mem_write_hook = 0;
  }
  if (g_discovery_buffer_read_hook) {
    uc_hook_del(uc, g_discovery_buffer_read_hook);
    g_discovery_buffer_read_hook = 0;
  }
  if (g_chain_block_hook) {
    uc_hook_del(uc, g_chain_block_hook);
    g_chain_block_hook = 0;
  }
  g_in_discovery_mode = false;
  g_buffer_fill_active = false;
}

// Reset all tracker state for re-population
void reset_all_tracker_state(void) {
  main_dt_array_index = 0;
  irq_dt_array_index = 0;
  pending_dt_array_index = 0;
  memset(main_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(irq_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(pending_dt_array, 0, MAX_PENDING_DRS * sizeof(DataTracker));

  // Clear hash table by re-creating it
  if (hash_table) {
    kh_destroy(dr_dt, hash_table);
  }
  hash_table = kh_init(dr_dt);

  // Reset discovery state
  g_in_discovery_mode = false;
  g_discovery_dr = 0;
  g_discovery_taint = 0;
  g_discovery_irq_pc = 0;
  g_discovery_addr_count = 0;
  g_discovery_buffer_addr = 0;
  g_discovery_mem_read_hook = 0;
  g_discovery_mem_write_hook = 0;
  g_discovery_occurred = false;

  // Reset fill + read_pc state
  g_discovery_read_pc = 0;
  g_discovery_callread_pc = 0;
  g_discovery_buffer_read_hook = 0;
  g_read_pc_done = false;
  g_buffer_fill_active = false;
  g_buffer_fill_done = false;
  g_fill_irq_num = 0;
  g_chain_min = 0;
  g_chain_max = 0;
  g_chain_extend_count = 0;
  g_consecutive_miss = 0;
  g_chain_idle_bb = 0;
  g_chain_block_hook = 0;
  g_bufmin_state = 0;
  g_bufmin_count = 0;
  g_bufmin_avail_hook = 0;
  g_bufmin_finish_hook = 0;
  g_bufmin_read_hook = 0;

  reset_datatrcker_and_global_vars();
}

// Minimal JSON integer/hex parser: extract value for a given key from a JSON object string
// Returns 0 if not found
static uint32_t json_extract_int(const char *json_obj, const char *key) {
  char search[128];
  snprintf(search, sizeof(search), "\"%s\":", key);
  const char *pos = strstr(json_obj, search);
  if (!pos) return 0;
  pos += strlen(search);

  // Skip whitespace
  while (*pos == ' ' || *pos == '\t') pos++;

  if (*pos == '"') {
    // Hex string like "0x..."
    pos++;
    uint32_t val = 0;
    if (strncmp(pos, "0x", 2) == 0) {
      sscanf(pos, "%x", &val);
    } else {
      sscanf(pos, "%u", &val);
    }
    return val;
  } else {
    // Plain integer
    int val = 0;
    sscanf(pos, "%d", &val);
    return (uint32_t)val;
  }
}

// Reload DT arrays from JSON file
void json_reload_dt_arrays(uc_engine *uc) {
  if (g_json_file_path[0] == 0) {
    printf("[JSON_RELOAD] No JSON path configured, skipping\n");
    return;
  }

  FILE *fp = fopen(g_json_file_path, "r");
  if (!fp) {
    printf("[JSON_RELOAD] File not found: %s, starting fresh\n", g_json_file_path);
    return;
  }

  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  rewind(fp);
  if (fsize <= 0 || fsize > 1048576) {  // max 1MB
    fclose(fp);
    return;
  }

  char *buf = malloc(fsize + 1);
  if (!buf) { fclose(fp); return; }
  fread(buf, 1, fsize, fp);
  buf[fsize] = '\0';
  fclose(fp);

  // Parse irq_dt_set array
  const char *irq_section = strstr(buf, "\"irq_dt_set\":");
  if (irq_section) {
    const char *p = strstr(irq_section, "[");
    if (p) {
      p++; // skip '['
      while (*p) {
        // Skip whitespace and stop if array ended
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == ']') break;
        // Find next DT object
        const char *obj_start = strstr(p, "{");
        if (!obj_start) break;
        const char *obj_end = strstr(obj_start, "}");
        if (!obj_end) break;

        // Extract fields
        uint32_t dr = json_extract_int(obj_start, "dr");
        if (dr == 0) { p = obj_end + 1; continue; }

        uint32_t callread_pc = json_extract_int(obj_start, "callread_pc");
        uint32_t read_pc     = json_extract_int(obj_start, "read_pc");
        uint32_t buffer_addr = json_extract_int(obj_start, "buffer_addr");
        uint32_t irq_pc      = json_extract_int(obj_start, "irq_pc");
        uint32_t avail_pc    = json_extract_int(obj_start, "avail_pc");
        uint32_t rx_head     = json_extract_int(obj_start, "rx_head");
        uint32_t rx_tail     = json_extract_int(obj_start, "rx_tail");
        short buffer_len     = (short)json_extract_int(obj_start, "buffer_len");
        short buffer_min_len = (short)json_extract_int(obj_start, "buffer_min_len");
        int consume_count    = (int)json_extract_int(obj_start, "consume_count");

        printf("[JSON_RELOAD] irq_dt: dr=0x%x irq_pc=0x%x buf=0x%x avail=0x%x\n",
               dr, irq_pc, buffer_addr, avail_pc);

        fill_data_tracker_irq_dt_array(dr, callread_pc, read_pc, buffer_addr,
                                       irq_pc, avail_pc, rx_head, rx_tail,
                                       buffer_len, buffer_min_len, consume_count,
                                       vtor_num);
        // Extract per-DT consume_pc_set
        {
          const char *cp = strstr(obj_start, "\"consume_pc_set\":");
          if (cp && cp < obj_end) {
            const char *s = strstr(cp, "[");
            const char *e = strstr(cp, "]");
            if (s && e && e > s && e < obj_end) {
              int n = e - s + 1;
              if (n < 256) {
                memcpy(irq_dt_array[irq_dt_array_index-1].consume_pcs, s, n);
                irq_dt_array[irq_dt_array_index-1].consume_pcs[n] = 0;
              }
            }
          }
        }

        p = obj_end + 1;
        // Stop at array boundary: if ] appears before next {, we're done
        const char *next_brace = strstr(p, "{");
        const char *next_bracket = strstr(p, "]");
        if (!next_brace || (next_bracket && next_bracket < next_brace)) break;
      }
    }
  }

  // Parse main_dt_set array
  const char *main_section = strstr(buf, "\"main_dt_set\":");
  if (main_section) {
    const char *p = strstr(main_section, "[");
    if (p) {
      p++;
      while (*p) {
        // Skip whitespace and stop if array ended
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == ']') break;
        const char *obj_start = strstr(p, "{");
        if (!obj_start) break;
        const char *obj_end = strstr(obj_start, "}");
        if (!obj_end) break;

        uint32_t dr = json_extract_int(obj_start, "dr");
        if (dr == 0) { p = obj_end + 1; continue; }

        uint32_t callread_pc = json_extract_int(obj_start, "callread_pc");
        uint32_t read_pc     = json_extract_int(obj_start, "read_pc");
        uint32_t buffer_addr = json_extract_int(obj_start, "buffer_addr");
        uint32_t irq_pc      = json_extract_int(obj_start, "irq_pc");
        uint32_t avail_pc    = json_extract_int(obj_start, "avail_pc");
        uint32_t rx_head     = json_extract_int(obj_start, "rx_head");
        uint32_t rx_tail     = json_extract_int(obj_start, "rx_tail");
        short buffer_len     = (short)json_extract_int(obj_start, "buffer_len");
        short buffer_min_len = (short)json_extract_int(obj_start, "buffer_min_len");
        int consume_count    = (int)json_extract_int(obj_start, "consume_count");

        printf("[JSON_RELOAD] main_dt: dr=0x%x read_pc=0x%x avail=0x%x\n",
               dr, read_pc, avail_pc);

        fill_data_tracker_main_dt_array(dr, callread_pc, read_pc, buffer_addr,
                                        irq_pc, avail_pc, rx_head, rx_tail,
                                        buffer_len, buffer_min_len, consume_count);
        // Extract per-DT consume_pc_set
        {
          const char *cp = strstr(obj_start, "\"consume_pc_set\":");
          if (cp && cp < obj_end) {
            const char *s = strstr(cp, "[");
            const char *e = strstr(cp, "]");
            if (s && e && e > s && e < obj_end) {
              int n = e - s + 1;
              if (n < 256) {
                memcpy(main_dt_array[main_dt_array_index-1].consume_pcs, s, n);
                main_dt_array[main_dt_array_index-1].consume_pcs[n] = 0;
              }
            }
          }
        }

        p = obj_end + 1;
        // Stop at array boundary
        const char *next_brace2 = strstr(p, "{");
        const char *next_bracket2 = strstr(p, "]");
        if (!next_brace2 || (next_bracket2 && next_bracket2 < next_brace2)) break;
      }
    }
  }

  free(buf);

  printf("[JSON_RELOAD] loaded %d irq_dt + %d main_dt\n",
         irq_dt_array_index, main_dt_array_index);
}

// Check if a DR address is already managed by a known DT
static bool dr_has_known_dt(uint32_t dr) {
  khint_t k = kh_get(dr_dt, hash_table, dr);
  return (k != kh_end(hash_table));
}

// Rebuild placeholder DTs and monitor hooks for unknown DRs
void rebuild_pending_drs(uc_engine *uc) {
  for (int i = 0; i < g_num_dr_addrs; i++) {
    uint32_t dr = g_all_dr_addrs[i];

    // Skip if already has a known DT (from JSON)
    if (dr_has_known_dt(dr)) {
      continue;
    }

    // Skip if already has a pending entry
    bool already_pending = false;
    for (int j = 0; j < pending_dt_array_index; j++) {
      if (pending_dt_array[j].dr == dr) {
        already_pending = true;
        break;
      }
    }
    if (already_pending) continue;

    // Create placeholder DataTracker
    DataTracker *dt = &pending_dt_array[pending_dt_array_index];
    memset(dt, 0, sizeof(DataTracker));
    dt->dr = dr;

    // Fill FIFO with magic token 0xAA as initial taint
    memset(dt->fifo, 0xAA, 1);
    dt->fifo_head = 1;
    dt->fifo_tail = 0;

    // Insert into hash table
    int ret = 0;
    khint_t k = kh_put(dr_dt, hash_table, dr, &ret);
    if (ret != -1) {
      kh_value(hash_table, k) = dt;
    }

    // Add MEM_READ_AFTER hook for this DR
    uc_hook hook_handle = 0;
    uc_err err = uc_hook_add(uc, &hook_handle, UC_HOOK_MEM_READ_AFTER,
                              hook_pending_dr_read_after, NULL, dr, dr);
    if (err == UC_ERR_OK && g_num_pending_hooks < MAX_PENDING_HOOKS) {
      g_pending_hook_handles[g_num_pending_hooks++] = hook_handle;
    }

    pending_dt_array_index++;
    printf("[PENDING] DR 0x%x: placeholder created, magic=fifo[0..3]=0xAA\n", dr);
  }
  printf("[PENDING] Total %d pending DRs with monitor hooks\n", pending_dt_array_index);
}

// Per-round reload: called after restore_snapshot when discovery occurred
int per_round_reload(uc_engine *uc) {
  printf("[PER_ROUND] Starting reload...\n");
  fflush(stdout);

  // 1. Clean up old hooks
  cleanup_avail_and_pending_hooks(uc);

  // 2. Reset state
  reset_all_tracker_state();

  // 3. Read JSON & fill known DT arrays
  json_reload_dt_arrays(uc);

  // 4. Add avail hooks for known DTs
  ufuzz_adapter_add_avail_hook(uc);

  // 5. Start buffer_min_len inference for first DT that needs it
  if (g_bufmin_state == 0) {
    for (int i = 0; i < irq_dt_array_index; i++) {
      DataTracker *dt = &irq_dt_array[i];
      if (dt->avail_pc && dt->buffer_min_len == 0) {
        g_bufmin_dt_idx = i;
        g_bufmin_state = 1;
        g_bufmin_count = 0;
        g_bufmin_irq = 0;  // resolved lazily on first avail hit
        g_bufmin_read_off = dt->buffer_addr;
        // Remove fuzzing avail hooks, replace with learning hook
        for (int j = 0; j < g_num_avail_hooks; j++)
          uc_hook_del(uc, g_avail_hook_handles[j]);
        g_num_avail_hooks = 0;
        uc_hook_add(uc, &g_bufmin_avail_hook, UC_HOOK_CODE,
                    hook_bufmin_avail, NULL,
                    dt->avail_pc, dt->avail_pc);
        // bufmin shepherd removed — learning persists across rounds
        printf("[BUFMIN] learning DT[%d]: avail_pc=0x%x irq=%d "
               "buf=0x%x callread=0x%x\n",
               i, dt->avail_pc, g_bufmin_irq,
               dt->buffer_addr, dt->callread_pc);
        fflush(stdout);
        FILE *fp = fopen("/tmp/bufmin.log", "w");
        if (fp) { fprintf(fp, "bufmin_start dt=%d avail=0x%x\n", i, dt->avail_pc); fclose(fp); }
        break;
      }
    }
  }

  // 5. Create placeholder DTs for unknown DRs
  rebuild_pending_drs(uc);

  // // 6. Init delivery budget
  // init_delivery_budget();

  printf("[PER_ROUND] Reload complete: %d main_dt, %d irq_dt, %d pending\n",
         main_dt_array_index, irq_dt_array_index, pending_dt_array_index);
  return 0;
}

// ====== Channel Discovery: JSON Append Helpers ======

// Write a complete JSON file with semu-fuzz compatible format
static int write_full_json(void) {
  if (g_json_file_path[0] == 0) return -1;

  FILE *fp = fopen(g_json_file_path, "w");
  if (!fp) {
    printf("[JSON_WRITE] Cannot open %s for writing\n", g_json_file_path);
    return -1;
  }

  fprintf(fp, "{\n");

  // irq_dt_set
  fprintf(fp, "  \"irq_dt_set\": [\n");
  for (int i = 0; i < irq_dt_array_index; i++) {
    DataTracker *dt = &irq_dt_array[i];
    fprintf(fp, "    {\"dr\": \"0x%x\", \"callread_pc\": \"0x%x\", "
            "\"read_pc\": \"0x%x\", \"buffer_addr\": \"0x%x\", "
            "\"irq_pc\": \"0x%x\", \"avail_pc\": \"0x%x\", "
            "\"rx_head\": %u, \"rx_tail\": %u, "
            "\"buffer_len\": %d, \"buffer_min_len\": %d, "
            "\"consume_count\": 0, "
            "\"consume_pc_set\": %s}%s\n",
            dt->dr, dt->callread_pc, dt->read_pc, dt->buffer_addr,
            dt->irq_pc, dt->avail_pc, dt->rx_head, dt->rx_tail,
            dt->buffer_len, dt->buffer_min_len,
            dt->consume_pcs[0] ? dt->consume_pcs : "[]",
            (i < irq_dt_array_index - 1 || main_dt_array_index > 0) ? "," : "");
  }
  fprintf(fp, "  ],\n");

  // main_dt_set
  fprintf(fp, "  \"main_dt_set\": [\n");
  for (int i = 0; i < main_dt_array_index; i++) {
    DataTracker *dt = &main_dt_array[i];
    fprintf(fp, "    {\"dr\": \"0x%x\", \"callread_pc\": \"0x%x\", "
            "\"read_pc\": \"0x%x\", \"buffer_addr\": \"0x%x\", "
            "\"irq_pc\": \"0x%x\", \"avail_pc\": \"0x%x\", "
            "\"rx_head\": %u, \"rx_tail\": %u, "
            "\"buffer_len\": %d, \"buffer_min_len\": %d, "
            "\"consume_count\": 0, "
            "\"consume_pc_set\": %s}%s\n",
            dt->dr, dt->callread_pc, dt->read_pc, dt->buffer_addr,
            dt->irq_pc, dt->avail_pc, dt->rx_head, dt->rx_tail,
            dt->buffer_len, dt->buffer_min_len,
            dt->consume_pcs[0] ? dt->consume_pcs : "[]",
            (i < main_dt_array_index - 1) ? "," : "");
  }
  fprintf(fp, "  ],\n");

  // dt_created_dr
  fprintf(fp, "  \"dt_created_dr\": [");
  int created_count = 0;
  for (int i = 0; i < irq_dt_array_index; i++) {
    fprintf(fp, "%s\"0x%x\"", created_count > 0 ? ", " : "", irq_dt_array[i].dr);
    created_count++;
  }
  for (int i = 0; i < main_dt_array_index; i++) {
    fprintf(fp, "%s\"0x%x\"", created_count > 0 ? ", " : "", main_dt_array[i].dr);
    created_count++;
  }
  fprintf(fp, "],\n");

  // Remaining fields (empty, for semu-fuzz compatibility)
  fprintf(fp, "  \"blacklist\": [],\n");
  fprintf(fp, "  \"indirect_src_addrs\": [],\n");
  fprintf(fp, "  \"data_regs\": [],\n");
  fprintf(fp, "  \"avail_dt_dict\": {},\n");
  fprintf(fp, "  \"consume_dt_dict\": {},\n");
  fprintf(fp, "  \"global_vars\": []\n");
  fprintf(fp, "}\n");

  fclose(fp);
  printf("[JSON_WRITE] Wrote %d irq_dt + %d main_dt to %s\n",
         irq_dt_array_index, main_dt_array_index, g_json_file_path);
  return 0;
}

// ====== Ghidra callback management ======

void set_ghidra_callback(void *cb) {
    g_ghidra_callback = cb;
}

// ====== Channel Discovery: Callbacks ======

// UC_HOOK_MEM_READ_AFTER callback for pending DRs
void hook_pending_dr_read_after(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  uint32_t dr = (uint32_t)address;

  if (g_in_discovery_mode) {
    // Already in discovery, ignore further DR reads
    return;
  }

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  uint32_t pc = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);

  if (ipsr != 0) {
    // === IRQ context → interrupt-read type ===
    printf("[DISCOVERY] DR 0x%x read in IRQ (ipsr=0x%x, pc=0x%x)\n",
           dr, ipsr, pc);

    g_discovery_dr = dr;
    g_discovery_taint = 0xAA;  // magic token byte, not full word

    // Read VTOR from CPU register
    uint32_t vtor = 0;
    uc_mem_read(uc, 0xE000ED08, &vtor, 4);
    vtor_num = vtor;  // also cache globally

    // Calculate IRQ PC from vector table
    uint64_t handler_addr = vtor + ((uint64_t)ipsr * 4);
    uint32_t handler_val = 0;
    uc_mem_read(uc, handler_addr, &handler_val, sizeof(handler_val));
    g_discovery_irq_pc = handler_val - 1;  // thumb bit adjustment

    printf("[DISCOVERY] irq_pc=0x%x (from VTOR=0x%x + ipsr=%d*4)\n",
           g_discovery_irq_pc, vtor, ipsr);

    // // Remove ALL pending DR hooks to prevent interference this round.
    // // They will be properly rebuilt by per_round_reload next round.
    // for (int i = 0; i < g_num_pending_hooks; i++) {
    //   if (g_pending_hook_handles[i]) {
    //     uc_hook_del(uc, g_pending_hook_handles[i]);
    //     g_pending_hook_handles[i] = 0;
    //   }
    // }
    // g_num_pending_hooks = 0;

    // Add global discovery tracking hooks
    uc_hook_add(uc, &g_discovery_mem_write_hook, UC_HOOK_MEM_WRITE,
                hook_discovery_mem_write, NULL, 0, 0xFFFFFFFF);
    uc_hook_add(uc, &g_discovery_mem_read_hook, UC_HOOK_MEM_READ_AFTER,
                hook_discovery_mem_read, NULL, 0, 0xFFFFFFFF);

    g_in_discovery_mode = true;
    g_discovery_addr_count = 0;
    g_discovery_buffer_addr = 0;

  } else {
    // === Main loop context → firmware-read type (main_read) ===
    printf("[DISCOVERY] DR 0x%x read in MAIN (pc=0x%x)\n", dr, pc);

    uint32_t lr = 0;
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);

    // Create main_dt with read_pc and callread_pc
    DataTracker *dt = &main_dt_array[main_dt_array_index];
    memset(dt, 0, sizeof(DataTracker));
    dt->dr = dr;
    dt->read_pc = pc;
    dt->callread_pc = lr;  // raw LR, corrected by Ghidra correct_lr later
    dt->irq_pc = 0;
    dt->buffer_addr = 0;
    dt->avail_pc = 0;  // deferred to static analysis

    // Insert into hash table
    int ret = 0;
    khint_t k = kh_put(dr_dt, hash_table, dr, &ret);
    if (ret != -1) {
      kh_value(hash_table, k) = dt;
    }
    main_dt_array_index++;

    printf("[DISCOVERY] main_read DT created: dr=0x%x read_pc=0x%x callread_pc=0x%x\n",
           dr, pc, lr - 1);

    // Signal Ghidra daemon: write JSON path to pending file
    if (g_ghidra_callback) {
      int fd = open("/tmp/ghidra_pending", O_CREAT | O_WRONLY | O_TRUNC, 0600);
      if (fd >= 0) {
        write(fd, g_json_file_path, strlen(g_json_file_path));
        close(fd);
      }
    }

    // Write updated JSON
    write_full_json();

    g_discovery_occurred = true;
    do_exit(uc, UC_ERR_OK);
  }
}

// UC_HOOK_MEM_WRITE callback during discovery — track buffer writes
void hook_discovery_mem_write(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  if (!g_in_discovery_mode) return;

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  if (ipsr != 0) {
    // ---- In IRQ context: track taint-matching writes ----
    if ((uint32_t)value == g_discovery_taint) {
      // Always track write addresses (Phase 1 buffer-addr discovery)
      if (g_discovery_addr_count < MAX_DISCOVERY_ADDRS) {
        g_discovery_addr_list[g_discovery_addr_count++] = (uint32_t)address;
        printf("[DISCOVERY] Tracked write #%d: addr=0x%x val=0x%x\n",
               g_discovery_addr_count, (uint32_t)address, (uint32_t)value);
      }

      // Buffer fill: chain tracking (+1, parallel with read_pc)
      if (g_buffer_fill_active && !g_buffer_fill_done) {
        if (chain_try_extend((uint32_t)address)) {
          g_chain_idle_bb = 0;
          g_consecutive_miss = 0;
        } else if (++g_consecutive_miss >= 5 && g_chain_extend_count > 1) {
          printf("[DISCOVERY] FILL: done (%d consecutive misses, %d ext). "
                 "min=0x%x max=0x%x len=%d\n",
                 g_consecutive_miss, g_chain_extend_count,
                 g_chain_min, g_chain_max,
                 g_chain_max - g_chain_min + 1);
          g_buffer_fill_done = true;
          if (g_discovery_mem_read_hook)  { uc_hook_del(uc, g_discovery_mem_read_hook);  g_discovery_mem_read_hook  = 0; }
          if (g_discovery_mem_write_hook) { uc_hook_del(uc, g_discovery_mem_write_hook); g_discovery_mem_write_hook = 0; }
          if (g_chain_block_hook)         { uc_hook_del(uc, g_chain_block_hook);         g_chain_block_hook         = 0; }
        }
      }
    }
  } else {
    // ---- In main loop context ----
    if (g_discovery_addr_count > 0 && g_discovery_buffer_addr == 0) {
      // buffer_addr just found → start parallel fill + read_pc capture
      g_discovery_buffer_addr =
          g_discovery_addr_list[g_discovery_addr_count - 1];
      printf("[DISCOVERY] IRQ exited. Buffer addr = 0x%x (from %d writes)\n",
             g_discovery_buffer_addr, g_discovery_addr_count);

      // ---- start buffer fill (refill + manual IRQ) ----
      g_buffer_fill_active = true;
      g_chain_min = g_discovery_buffer_addr;
      g_chain_max = g_discovery_buffer_addr;
      // start from buffer_addr, like semu_fuzz's offset=buffer_addr
      g_chain_extend_count = 1;   // Phase 0 already wrote buffer_addr
      g_consecutive_miss = 0;
      g_chain_idle_bb = 0;
      g_fill_irq_num = get_match_irq_num(uc, g_discovery_irq_pc);

      // Prime DT FIFO & pend IRQ to kick off fill loop
      {
        khint_t k = kh_get(dr_dt, hash_table, g_discovery_dr);
        if (k != kh_end(hash_table)) {
          DataTracker *pdt = kh_value(hash_table, k);
          memset(pdt->fifo, 0xAA, 1);
          pdt->fifo_head = 1;
          pdt->fifo_tail = 0;
        }
      }
      if (g_fill_irq_num) {
        nvic_set_pending(uc, g_fill_irq_num, false);
      }
      printf("[DISCOVERY] FILL: started. irq=%d, pend sent\n", g_fill_irq_num);

      // ---- start chain convergence block hook ----
      uc_hook_add(uc, &g_chain_block_hook, UC_HOOK_BLOCK,
                  hook_chain_block, NULL, 1, 0);

      // ---- hook buffer read for parallel read_pc capture ----
      uc_hook_add(uc, &g_discovery_buffer_read_hook, UC_HOOK_MEM_READ_AFTER,
                  hook_phase1_buffer_read, NULL,
                  g_discovery_buffer_addr, g_discovery_buffer_addr);
    }

    // ---- semu-fuzz end condition: ISR exited, fill was active ----
    // During fill loop, nvic_set_pending re-enters ISR immediately,
    // so ipsr==0 only fires when fill stops (buffer full / ISR won't re-enter).
    if (g_buffer_fill_active && !g_buffer_fill_done) {
      if (g_chain_extend_count > 1) {
        printf("[DISCOVERY] FILL: done (ISR exited, %d extensions). "
               "min=0x%x max=0x%x len=%d\n",
               g_chain_extend_count, g_chain_min, g_chain_max,
               g_chain_max - g_chain_min + 1);
        g_buffer_fill_done = true;
        // Delete global hooks immediately (like semu_fuzz), read_pc uses its own hook
        if (g_discovery_mem_read_hook)  { uc_hook_del(uc, g_discovery_mem_read_hook);  g_discovery_mem_read_hook  = 0; }
        if (g_discovery_mem_write_hook) { uc_hook_del(uc, g_discovery_mem_write_hook); g_discovery_mem_write_hook = 0; }
        if (g_chain_block_hook)         { uc_hook_del(uc, g_chain_block_hook);         g_chain_block_hook         = 0; }
      }
    }
    try_finalize(uc);
  }
}

// UC_HOOK_MEM_READ_AFTER callback during discovery — update taint
void hook_discovery_mem_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  if (!g_in_discovery_mode) return;

  if (address == g_discovery_dr) {
    g_discovery_taint = 0xAA;
    printf("[DISCOVERY] Taint updated: DR 0x%x re-read\n", (uint32_t)address);

    // Buffer fill: refill DT FIFO and pend IRQ for next read
    if (g_buffer_fill_active && !g_buffer_fill_done) {
      khint_t k = kh_get(dr_dt, hash_table, (uint32_t)address);
      if (k != kh_end(hash_table)) {
        DataTracker *dt = kh_value(hash_table, k);
        memset(dt->fifo, 0xAA, 1);
        dt->fifo_head = 1;
        dt->fifo_tail = 0;
      }
      if (g_fill_irq_num) {
        nvic_set_pending(uc, g_fill_irq_num, false);
      }
    }
  }
}

// ====== Channel Discovery: Phase 1 buffer read callback ======

// Fires when main loop reads the discovered buffer address.
// Captures read_pc (PC at buffer read) and callread_pc (LR = caller).
// Runs in PARALLEL with buffer fill (refill + manual IRQ loop).
void hook_phase1_buffer_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  if (!g_in_discovery_mode) return;
  if (g_read_pc_done) return;

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  if (ipsr != 0) return; // only capture in main loop

  uint32_t pc = 0;
  uint32_t lr = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  uc_reg_read(uc, UC_ARM_REG_LR, &lr);

  g_discovery_read_pc = pc;
  g_discovery_callread_pc = lr;  // raw LR, corrected by Ghidra correct_lr later
  g_read_pc_done = true;

  if (g_discovery_buffer_read_hook) {
    uc_hook_del(uc, g_discovery_buffer_read_hook);
    g_discovery_buffer_read_hook = 0;
  }

  printf("[DISCOVERY] read_pc=0x%x callread_pc=0x%x (lr=0x%x)\n",
         g_discovery_read_pc, g_discovery_callread_pc, lr);

  try_finalize(uc);
}

// ====== Buffer fill: chain tracking ======

// Semu-fuzz style: addr == chain_max + 1. Noise is silently ignored.
static bool chain_try_extend(uint32_t addr) {
  if (addr == g_chain_max + 1) {
    g_chain_max = addr;
    g_chain_extend_count++;
    printf("[DISCOVERY] FILL: chain +1 → 0x%x (#%d)\n", addr, g_chain_extend_count);
    return true;
  }
  return false;
}

// ====== Buffer minimum length inference (semu-fuzz: hook_func_got_buffer_min_len) ======

// Called at avail_pc: put 1 byte into DT FIFO and pend IRQ.
// Each invocation increments the counter.  First call also sets up finish + read-ptr hooks.
static void hook_bufmin_avail(uc_engine *uc, uint64_t address, uint32_t size,
    void *user_data) {

  if (g_bufmin_state != 1) return;

  // Lazy irq_num resolution (NVIC not yet configured at per_round_reload time)
  if (!g_bufmin_irq && g_bufmin_dt_idx >= 0) {
    g_bufmin_irq = get_match_irq_num(uc, irq_dt_array[g_bufmin_dt_idx].irq_pc);
    if (g_bufmin_irq) irq_dt_array[g_bufmin_dt_idx].irq_num = g_bufmin_irq;
  }

  // First time: set default, register finish + read-ptr hooks
  if (!g_bufmin_finish_hook && g_bufmin_dt_idx >= 0) {
    DataTracker *dt = &irq_dt_array[g_bufmin_dt_idx];
    dt->buffer_min_len = 1;  // default minimum
    if (dt->callread_pc) {
      uc_hook_add(uc, &g_bufmin_finish_hook, UC_HOOK_CODE,
                  hook_bufmin_finish, NULL,
                  dt->callread_pc, dt->callread_pc);
      printf("[BUFMIN] finish hook at callread_pc=0x%x\n", dt->callread_pc);
    }
    if (dt->buffer_addr) {
      g_bufmin_read_off = dt->buffer_addr;
      uc_hook_add(uc, &g_bufmin_read_hook, UC_HOOK_MEM_READ,
                  hook_bufmin_read_ptr, NULL,
                  dt->buffer_addr, dt->buffer_addr);
      printf("[BUFMIN] read-ptr hook at buffer_addr=0x%x\n", dt->buffer_addr);
    }
  }

  // Put 1 byte into DT FIFO and pend IRQ (capped at buffer_len)
  if (g_bufmin_dt_idx >= 0) {
    DataTracker *dt = &irq_dt_array[g_bufmin_dt_idx];
    if (g_bufmin_count < dt->buffer_len) {
      memset(dt->fifo, 0xAA, 1);
      dt->fifo_head = 1;
      dt->fifo_tail = 0;
      g_bufmin_count++;
      printf("[BUFMIN] avail hit #%d/%d\n", g_bufmin_count, dt->buffer_len);
      if (g_bufmin_irq)
        nvic_set_pending(uc, g_bufmin_irq, false);
    } else {
      printf("[BUFMIN] avail hit ignored (reached limit %d)\n", dt->buffer_len);
    }
  }
}

// Called at callread_pc: check if bufmin learning is complete.
static void hook_bufmin_finish(uc_engine *uc, uint64_t address, uint32_t size,
    void *user_data) {

  if (g_bufmin_state != 1) return;
  if (g_bufmin_count == 0) return; // wait for first avail hit

  // Learning done!
  if (g_bufmin_dt_idx >= 0) {
    irq_dt_array[g_bufmin_dt_idx].buffer_min_len = (short)g_bufmin_count;
    printf("[BUFMIN] done: DT[%d] buffer_min_len=%d\n",
           g_bufmin_dt_idx, g_bufmin_count);
    fflush(stdout);
    FILE *fp = fopen("/tmp/bufmin.log", "a");
    if (fp) { fprintf(fp, "bufmin_done len=%d\n", g_bufmin_count); fclose(fp); }
  }

  // Cleanup hooks
  if (g_bufmin_avail_hook) { uc_hook_del(uc, g_bufmin_avail_hook); g_bufmin_avail_hook = 0; }
  if (g_bufmin_finish_hook) { uc_hook_del(uc, g_bufmin_finish_hook); g_bufmin_finish_hook = 0; }
  if (g_bufmin_read_hook)   { uc_hook_del(uc, g_bufmin_read_hook);   g_bufmin_read_hook = 0; }

  g_bufmin_state = 2;
  write_full_json();
  g_discovery_occurred = true;
  do_exit(uc, UC_ERR_OK);
}

// Buffer read pointer tracking (semu-fuzz: hook_func_buffer_pointer)
// Advances the hook by 1 byte each time the main loop reads from buffer.
static void hook_bufmin_read_ptr(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  if (g_bufmin_state != 1) return;

  // Delete old hook, advance offset, re-hook at new position
  if (g_bufmin_read_hook) {
    uc_hook_del(uc, g_bufmin_read_hook);
    g_bufmin_read_hook = 0;
  }
  g_bufmin_read_off++;
  uc_hook_add(uc, &g_bufmin_read_hook, UC_HOOK_MEM_READ,
              hook_bufmin_read_ptr, NULL,
              g_bufmin_read_off, g_bufmin_read_off);
}

// Hard timeout: fallback if fill doesn't end via ipsr==0 (e.g. ISR never exits)
static void hook_chain_block(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {

  if (!g_buffer_fill_active || g_buffer_fill_done) return;

  g_chain_idle_bb += size;
  if (g_chain_idle_bb < 500000) return;  // 500k BB hard timeout

  printf("[DISCOVERY] FILL: hard timeout after %d BBs. "
         "min=0x%x max=0x%x ext=%d len=%d\n",
         g_chain_idle_bb, g_chain_min, g_chain_max,
         g_chain_extend_count,
         g_chain_max >= g_chain_min ? g_chain_max - g_chain_min + 1 : 0);
  g_buffer_fill_done = true;
  if (g_discovery_mem_read_hook)  { uc_hook_del(uc, g_discovery_mem_read_hook);  g_discovery_mem_read_hook  = 0; }
  if (g_discovery_mem_write_hook) { uc_hook_del(uc, g_discovery_mem_write_hook); g_discovery_mem_write_hook = 0; }
  if (g_chain_block_hook)         { uc_hook_del(uc, g_chain_block_hook);         g_chain_block_hook         = 0; }
  try_finalize(uc);
}

// If both read_pc and fill are done, finalize.
static void try_finalize(uc_engine *uc) {
  if (g_read_pc_done && g_buffer_fill_done)
    finalize_discovery(uc);
}

// ====== Channel Discovery: finalize_discovery ======

static void finalize_discovery(uc_engine *uc) {
  // 1. Remove discovery hooks
  if (g_discovery_mem_read_hook) {
    uc_hook_del(uc, g_discovery_mem_read_hook);
    g_discovery_mem_read_hook = 0;
  }
  if (g_discovery_mem_write_hook) {
    uc_hook_del(uc, g_discovery_mem_write_hook);
    g_discovery_mem_write_hook = 0;
  }
  if (g_discovery_buffer_read_hook) {
    uc_hook_del(uc, g_discovery_buffer_read_hook);
    g_discovery_buffer_read_hook = 0;
  }
  if (g_chain_block_hook) {
    uc_hook_del(uc, g_chain_block_hook);
    g_chain_block_hook = 0;
  }
  g_in_discovery_mode = false;
  g_buffer_fill_active = false;

  // 2. Create full irq_dt from discovery data
  uint32_t dr = g_discovery_dr;
  DataTracker *dt = &irq_dt_array[irq_dt_array_index];
  memset(dt, 0, sizeof(DataTracker));
  dt->dr = dr;
  dt->irq_pc = g_discovery_irq_pc;
  dt->buffer_addr = g_discovery_buffer_addr;
  dt->read_pc = g_discovery_read_pc;
  dt->callread_pc = g_discovery_callread_pc;
  dt->avail_pc = 0;          // filled by Ghidra daemon later
  dt->buffer_min_len = 1;    // default 1 byte (bufmin disabled)

  // Compute buffer_len from chain tracking
  if (g_chain_extend_count > 0 && g_chain_max >= g_chain_min) {
    dt->buffer_len = (short)(g_chain_max - g_chain_min + 1);
  } else {
    dt->buffer_len = 0;
  }

  // Failed upper-bound inference: exit without saving, user should re-run
  if (dt->buffer_len <= 1) {
    printf("[DISCOVERY] buffer_len=%d — inference failed, retrying.\n",
           dt->buffer_len);
    fflush(stdout);
    do_exit(uc, UC_ERR_OK);
    return;
  }

  dt->rx_head = 0;
  dt->rx_tail = 0;

  // Signal Ghidra daemon: write JSON path to pending file
  if (g_ghidra_callback) {
    int fd = open("/tmp/ghidra_pending", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
      write(fd, g_json_file_path, strlen(g_json_file_path));
      close(fd);
    }
  }

  printf("[DISCOVERY] Final DT: dr=0x%x irq_pc=0x%x buf=0x%x "
         "read_pc=0x%x callread_pc=0x%x buffer_len=%d\n",
         dt->dr, dt->irq_pc, dt->buffer_addr,
         dt->read_pc, dt->callread_pc, dt->buffer_len);

  // Update hash table (replace placeholder)
  int ret = 0;
  khint_t k = kh_put(dr_dt, hash_table, dr, &ret);
  if (ret != -1) {
    kh_value(hash_table, k) = dt;
  }
  irq_dt_array_index++;

  // 3. Write updated JSON
  write_full_json();

  // Clean up pending reference to this DR
  for (int i = 0; i < pending_dt_array_index; i++) {
    if (pending_dt_array[i].dr == dr) {
      memset(&pending_dt_array[i], 0, sizeof(DataTracker));
      break;
    }
  }

  g_discovery_occurred = true;

  printf("[DISCOVERY] Complete: DR=0x%x irq_pc=0x%x buf=0x%x "
         "read_pc=0x%x callread_pc=0x%x buffer_len=%d\n",
         dr, g_discovery_irq_pc, g_discovery_buffer_addr,
         g_discovery_read_pc, g_discovery_callread_pc, dt->buffer_len);

  do_exit(uc, UC_ERR_OK);
}

bool fifo_get_fuzz(uc_engine *uc, DataTracker *dt, uint8_t *buf,
                   uint32_t size) {
  if (dt->fifo_head == dt->fifo_tail) {
    return true;
  }
  int available = dt->fifo_head - dt->fifo_tail;
  int copy_size = (available < (int)size) ? available : (int)size;
  memcpy(buf, &dt->fifo[dt->fifo_tail], copy_size);
  dt->fifo_tail += copy_size;
  return false;
}

int stop_for_firmware_read_datareg() {
  stop_count = 0;
  return stop_count;
}

int avail_cnt(uint64_t address) {
    // 获取进程号
    // pid_t pid = getpid();
    char filename[200];
    // 生成文件名
    snprintf(filename, sizeof(filename), "/home/n0vic3/fuzzers/fuzzware-examples/P2IM/avail_cnt/avail_cnt_0x%lx.txt",address);
    // 打开文件
    // printf("filename :%s\n", filename);
    FILE *fp = fopen(filename, "r+");
    if (fp == NULL) {
        // 文件不存在，创建并初始化
        fp = fopen(filename, "w+");
        if (fp == NULL) {
            perror("Error opening file");
            return 1;
        }
        // 初始化文件内容为 0
        fprintf(fp, "%d", 0);
        rewind(fp);
    }

    int num;
    // 读取文件中的数字
    if (fscanf(fp, "%d", &num)!= 1) {
        perror("Error reading from file");
        fclose(fp);
        return 1;
    }
    num++;  // 数字加 1
    rewind(fp);  // 重置文件指针到开头
    // 写回更新后的数字
    if (fprintf(fp, "%d", num) < 0) {
        perror("Error writing to file");
        fclose(fp);
        return 1;
    }
    fclose(fp);  // 关闭文件
    return 0;
  }