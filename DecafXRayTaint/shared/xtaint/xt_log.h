/*
 * xt_log.h
 */

#ifndef XT_LOG_H_
#define XT_LOG_H_

#include "qemu-common.h"

#define XT_MAX_POOL_SIZE (8 * 1024 * 1024)
#define XT_POOL_THRESHOLD (1024 * 1024)

extern uint8_t xt_pool[XT_MAX_POOL_SIZE];
extern uint8_t *xt_curr_record;
extern uint32_t xt_curr_pool_sz;

extern FILE *xt_log;

extern void xt_flushFile(FILE *);

#endif /* XT_LOG_H_ */
