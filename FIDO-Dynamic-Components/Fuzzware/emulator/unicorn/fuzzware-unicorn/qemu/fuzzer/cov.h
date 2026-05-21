#ifndef AFL_QEMU_H
#define AFL_QEMU_H

#include "uc_priv.h"

// 4K - 64K
#define COV_AREA_SIZE_MAX (1<<16)
#define COV_AREA_SIZE_MIN (1<<12)

extern unsigned char *cov_area_ptr;
extern unsigned long cov_prev_loc;
extern unsigned long cov_area_size;

void fuzzer_init_cov(uc_engine *uc, void *bitmap_region, uint32_t bitmap_size);
void fuzzer_reset_cov(uc_engine *uc, int do_clear);

#endif
