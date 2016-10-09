/*
 * xt_log.c
 */
#include "shared/xtaint/xt_log.h"

#ifdef CONFIG_TCG_XTAINT

uint8_t xt_pool[XT_MAX_POOL_SIZE];
uint8_t *xt_curr_record = xt_pool;
uint32_t xt_curr_pool_sz = XT_POOL_THRESHOLD;

FILE *xt_log = NULL;

void xt_flush_file(FILE *xt_log) {}

#endif /* CONFIG_TCG_XTAINT */
