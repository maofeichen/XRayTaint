/*
 * xt_log_ir.c
 */

#include "monitor.h" // For default_mon
#include "shared/xtaint/xt_log.h"
#include "shared/xtaint/xt_log_ir.h"
#include "shared/tainting/taint_memory.h"

#ifdef CONFIG_TCG_XTAINT

int XRAYTAINT_DEBUG = 1;

int xt_enable_log_ir = 1;

int xt_do_log_ir(Monitor *mon, const QDict *qdict, QObject **ret_data){
    if (!taint_tracking_enabled)
        monitor_printf(default_mon, "Ignored, taint tracking is disabled\n");
    else {
        CPUState *env;
        DECAF_stop_vm();
        env = cpu_single_env ? cpu_single_env : first_cpu;
        xt_enable_log_ir = qdict_get_bool(qdict, "load");
        DECAF_start_vm();
        tb_flush(env);
        monitor_printf(default_mon, "XRay Taint log ir changed -> %s\n",
                xt_enable_log_ir ? "ON " : "OFF");
    }
    return 0;
}

// Instrument XT ir
inline void XT_log_ir(TCGv srcShadow, TCGv src, TCGv dst, uint32_t flag)
{
	tcg_gen_XT_log_ir_i32(srcShadow, src, dst, flag);
}

void XT_debug_empty(){}

// Write both src and dst temporaries
void XT_write_tmp()
{
	register int ebp asm("ebp");
	unsigned int offset = 0x8;

	uint32_t *src_val = (uint32_t*)(ebp + offset);
	uint32_t *src_addr = (uint32_t*)(ebp + offset + 4);
	uint32_t *src_flag = (uint32_t*)(ebp + offset + 8);

	*(uint32_t *)xt_curr_record = *src_flag;
	xt_curr_record += 4;

	*(uint32_t *)xt_curr_record = *src_addr;
	xt_curr_record += 4;

	*(uint32_t *)xt_curr_record = *src_val;
	xt_curr_record += 4;

	xt_curr_pool_sz -= 12;
	if(xt_curr_pool_sz < XT_POOL_THRESHOLD){
		xt_flushFile(xt_log);
		xt_curr_record = xt_pool;
		xt_curr_pool_sz = XT_MAX_POOL_SIZE;
	}
}

// Write source temporary into temporary buffer
void XT_write_src_tmp()
{
	register int ebp asm("ebp");
	unsigned int offset = 0x8;

	uint32_t *src_val = (uint32_t*)(ebp + offset);
	uint32_t *src_addr = (uint32_t*)(ebp + offset + 4);
	uint32_t *src_flag = (uint32_t*)(ebp + offset + 8);

	*xt_curr_pos = *src_flag;
	xt_curr_pos++;
	*xt_curr_pos = *src_addr;
	xt_curr_pos++;
	*xt_curr_pos = *src_val;
	xt_curr_pos++;
}

// Write destination temporary into temporary buffer
void XT_write_dst_tmp()
{
	register int ebp asm("ebp");
	unsigned int offset = 0x8;

	uint32_t *src_val = (uint32_t*)(ebp + offset);
	uint32_t *src_addr = (uint32_t*)(ebp + offset + 4);
	uint32_t *src_flag = (uint32_t*)(ebp + offset + 8);

	*xt_curr_pos = *src_flag;
	xt_curr_pos++;
	*xt_curr_pos = *src_addr;
	xt_curr_pos++;
	*xt_curr_pos = *src_val;
	xt_curr_pos++;

	XT_flush_pool();
}

// flush the temporary buffer into xt pool
void XT_flush_pool()
{
	uint32_t *idx = xt_tmp_buf;
	int i = 0;

	for(; i < 6; i++){
		*(uint32_t *)xt_curr_record = *idx;
		idx++;
		xt_curr_record += 4;
	}

	// If hit threash, flush to file and reset
	xt_curr_pool_sz -= 24;
	if(xt_curr_pool_sz < XT_POOL_THRESHOLD){
		xt_flushFile(xt_log);
		xt_curr_record = xt_pool;
		xt_curr_pool_sz = XT_MAX_POOL_SIZE;
	}

	// reset the temporary buffer
	xt_curr_pos = xt_tmp_buf;
	memset(xt_tmp_buf, 0x0, sizeof(uint32_t)*12);
}

#endif /* CONFIG_TCG_XTAINT */

