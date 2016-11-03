/*
 * xt_log_ir.c
 */

#include "monitor.h" // For default_mon
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

inline void XT_log_ir(TCGv srcShadow, TCGv src, TCGv dst, uint32_t flag)
{
	tcg_gen_XT_log_ir_i32(srcShadow, src, dst, flag);
}

void XT_write_tmp()
{
	register int ebp asm("ebp");
	unsigned int offset = 16;

	uint32_t *src_val = (uint32_t*)(ebp + offset);
	uint32_t *src_addr = (uint32_t*)(ebp + offset + 4);
	uint32_t *src_flag = (uint32_t*)(ebp + 8);
}

#endif /* CONFIG_TCG_XTAINT */

