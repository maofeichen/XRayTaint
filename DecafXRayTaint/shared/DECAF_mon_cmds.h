/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

DECAF is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU GPL, version 3 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
{
.name       = "load_plugin",
.args_type  = "filename:F",
.params     = "filename",
.help       = "Load a DECAF plugin",
.mhandler.cmd_new = do_load_plugin,
},


{
.name       = "unload_plugin",
.args_type  = "",
.params     = "",
.help       = "Unload the current DECAF plugin",
.mhandler.cmd_new = do_unload_plugin,
},


/* operating system information */
{
	.name		= "guest_ps|ps",
	.args_type	= "",
	.mhandler.info	= do_guest_ps,
	.params		= "", 
	.help		= "list the processes on guest system"
},
{
	.name		= "lsmod",
	.args_type	= "",
	.mhandler.info	= do_print_modules,
	.params 	= "", 
	.help		= "list the loaded kernel modules"
},

{
	.name		= "guest_modules", 
	.args_type	= "pid:i", 
	.mhandler.cmd	= do_guest_modules,
	.params		= "pid",
	.help		= "list the modules of the process with <pid>"
},

{
	.name		= "toggle_kvm",
	.args_type	= "status:b",
	.mhandler.cmd	= do_toggle_kvm,
	.params		= "on|off",
	.help		= "turn kvm on or off at runtime"
},

#if 0 //To be removed
{
	.name		= "linux_ps",
	.args_type	= "mmap_flag:i?", 
	.mhandler.cmd	= do_linux_ps,
	.params		= "[mmap_flag]", 
	.help		= "list the processes on linux guest system (default: mmap_flag = 1)"
},
#endif

#ifdef CONFIG_TCG_TAINT
/* TCG tainting commands */
{
        .name       = "enable_tainting",
        .args_type  = "",
        .params     = "",
        .help       = "Turn on taint tracking",
        .mhandler.cmd = do_enable_tainting,
},
{
        .name       = "disable_tainting",
        .args_type  = "",
        .params     = "",
        .help       = "Turn off taint tracking",
        .mhandler.cmd = do_disable_tainting,
},
{
        .name       = "taint_nic_on",
        .args_type  = "",
        .params     = "",
        .help       = "Turn on tainting of all data coming from the NE2000 NIC",
        .mhandler.cmd = do_taint_nic_on,
},
{
        .name       = "taint_nic_off",
        .args_type  = "",
        .params     = "",
        .help       = "Turn off tainting of all data coming from the NE2000 NIC",
        .mhandler.cmd = do_taint_nic_off,
},
{
        .name       = "taint_mem_usage",
        .args_type  = "",
        .params     = "",
        .help       = "Print usage stats pertaining to tracking tainted memory",
        .mhandler.cmd = do_taint_mem_usage,
},
{
	.name       = "tainted_bytes",
	.args_type  = "",
	.params     = "",
	.help       = "Print the No. of tainted memory bytes",
	.mhandler.cmd = do_tainted_bytes,
},
{
        .name       = "taint_garbage_collect",
        .args_type  = "",
        .params     = "",
        .help       = "Manually garbage collect any unused taint-tracking memory",
        .mhandler.cmd = do_garbage_collect_taint,
},
{
        .name       = "taint_pointers",
        .args_type  = "load:b,store:b",
        .params     = "on|off on|off",
        .help       = "Turn on/off tainting of pointers (load) (store)",
        .mhandler.cmd_new = do_taint_pointers,
},
#ifdef CONFIG_TCG_XTAINT // mchen
{
        .name       = "xraytaint_log_ir",
        .args_type  = "load:b",
        .params     = "on|off",
        .help       = "Turn on/off xray taint log ir",
        .mhandler.cmd_new = xt_do_log_ir,
},
{
        .name       = "xraytaint_size_mark",
        .args_type  = "load:b",
        .params     = "on|off",
        .help       = "Turn on/off xray taint size mark for each qemu_ld/st",
        .mhandler.cmd_new = xt_do_size_mark,
},
{
        .name       = "xraytaint_func_mark",
        .args_type  = "load:b",
        .params     = "on|off",
        .help       = "Turn on/off xray taint function call mark",
        .mhandler.cmd_new = xt_do_func_mark,
},
{
        .name       = "xraytaint_insn_mark",
        .args_type  = "load:b",
        .params     = "on|off",
        .help       = "Turn on/off xray taint instruction mark",
        .mhandler.cmd_new = xt_do_insn_mark,
},
{
        .name       = "xraytaint_dbg_ide",
        .args_type  = "load:b",
        .params     = "on|off",
        .help       = "Turn on/off xray taint debug ide",
        .mhandler.cmd_new = do_debug_ide,
},

#endif /* #ifdef CONFIG_TCG_XTAINT */
#endif /* CONFIG_TCG_TAINT */

