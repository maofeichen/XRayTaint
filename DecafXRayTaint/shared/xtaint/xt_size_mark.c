/*
 * xt_size_mark.c
 */


#include "monitor.h" // For default_mon
#include "shared/xtaint/xt_size_mark.h"
#include "shared/tainting/taint_memory.h"

#ifdef CONFIG_TCG_XTAINT

int xt_enable_size_mark = 0;
int xt_do_size_mark(Monitor *mon, const QDict *qdict, QObject **ret_data)
{
    if (!taint_tracking_enabled)
        monitor_printf(default_mon, "Ignored, taint tracking is disabled\n");
    else {
        CPUState *env;
        DECAF_stop_vm();
        env = cpu_single_env ? cpu_single_env : first_cpu;
        xt_enable_size_mark = qdict_get_bool(qdict, "load");
        DECAF_start_vm();
        tb_flush(env);
        monitor_printf(default_mon, "XRay Taint size mark changed -> %s\n",
                xt_enable_size_mark ? "ON " : "OFF");
    }
    return 0;
}

// Add size mark for qemu_ld/st
inline int assign_size_flag(uint16_t opc)
{
	uint32_t size_flag = 0;
	switch(opc){
		case INDEX_op_qemu_ld8u:
		case INDEX_op_qemu_ld8s:
		case INDEX_op_qemu_st8:
			size_flag = XT_BYTE;
			break;
		case INDEX_op_qemu_ld16u:
		case INDEX_op_qemu_ld16s:
		case INDEX_op_qemu_st16:
			size_flag = XT_WORD;
			break;
		case INDEX_op_qemu_ld32:
		case INDEX_op_qemu_st32:
			size_flag = XT_DOUBLE_WORD;
			break;
		default:
			fprintf(stderr, "Unknown size mark, abort\n");
			abort();
			break;
	}
	return size_flag;
}

#endif /* CONFIG_TCG_XTAINT */
