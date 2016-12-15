/*
 * xt_log.c
 */
#include "shared/xtaint/xt_flag.h"
#include "shared/xtaint/xt_log.h"
#include "shared/xtaint/xt_log_ir.h"

#ifdef CONFIG_TCG_XTAINT

uint8_t xt_pool[XT_MAX_POOL_SIZE];
uint8_t *xt_curr_record = xt_pool;
uint32_t xt_curr_pool_sz = XT_POOL_THRESHOLD;

FILE *xt_log = NULL;

uint32_t xt_tmp_buf[XT_BUF_POOL_SZ];
uint32_t *xt_curr_pos = xt_tmp_buf;

void xt_flushFile(FILE *xt_log)
{
	uint8_t *idx = xt_pool;
	int i;

	while(idx < xt_curr_record){
		if(*idx == XT_SIZE_BEGIN || \
		   *idx == XT_SIZE_END	|| \
		   *idx == XT_INSN_CALL || \
		   *idx == XT_INSN_CALL_SEC || \
		   *idx == XT_INSN_CALL_FF2 || \
		   *idx == XT_INSN_CALL_FF2_SEC || \
		   *idx == XT_INSN_RET || \
		   *idx == XT_INSN_RET_SEC || \
		   *idx == XT_INSN_ADDR){
			for(i = 0; i < 3; i++){
				fprintf(xt_log, "%x\t", *(uint32_t*) idx);
				idx += 4;
			}
			fprintf(xt_log, "\n");
		}else{
			for(i = 0; i < 6; i++){
				fprintf(xt_log, "%x\t", *(uint32_t*) idx);
				idx += 4;
			}
			fprintf(xt_log, "\n");
		}
	}
}

#endif /* CONFIG_TCG_XTAINT */
