/*
 * xt_func_mark.c
 */

#include "monitor.h" // For default_mon
#include "shared/xtaint/xt_func_mark.h"
#include "shared/tainting/taint_memory.h"

#ifdef CONFIG_TCG_XTAINT

int xt_enable_func_mark = 0;

int xt_do_func_mark(Monitor *mon, const QDict *qdict, QObject **ret_data){
    if (!taint_tracking_enabled)
        monitor_printf(default_mon, "Ignored, taint tracking is disabled\n");
    else {
        CPUState *env;
        DECAF_stop_vm();
        env = cpu_single_env ? cpu_single_env : first_cpu;
        xt_enable_func_mark = qdict_get_bool(qdict, "load");
        DECAF_start_vm();
        tb_flush(env);
        monitor_printf(default_mon, "xray taint function call mark changed -> %s\n",
        		xt_enable_func_mark ? "ON " : "OFF");
    }
    return 0;
}

#endif /* CONFIG_TCG_XTAINT */


