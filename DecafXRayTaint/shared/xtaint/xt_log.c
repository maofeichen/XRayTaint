/*
 * xt_log.c
 */
#include "shared/xtaint/xt_log.h"
#include "shared/xtaint/xt_log_ir.h"

#ifdef CONFIG_TCG_XTAINT

uint8_t xt_pool[XT_MAX_POOL_SIZE];
uint8_t *xt_curr_record = xt_pool;
uint32_t xt_curr_pool_sz = XT_POOL_THRESHOLD;

FILE *xt_log = NULL;

uint32_t xt_tmp_buf[12];
uint32_t *xt_curr_pos = xt_tmp_buf;

void xt_flushFile(FILE *xt_log)
{
	uint8_t *idx = xt_pool;

	while(idx < xt_curr_record){
		int i = 0;
		for(; i < 6; i++){
			fprintf(xt_log, "%x\t", *(uint32_t*) idx);
			idx += 4;
		}
		fprintf(xt_log, "\n");
	}
}

#endif /* CONFIG_TCG_XTAINT */
