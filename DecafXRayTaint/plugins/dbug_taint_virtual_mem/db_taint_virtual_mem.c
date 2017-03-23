/*
 * db_taint_virtual_mem.c
 *
 * This file uses to debug the taint_virtual_mem plugin. There is a bug in
 * the plugin that it missies tainting the last 4 bytes of a target buf,
 * when using sys call: read() to read a file to the target buffer.
 *
 * Is it a bug of Decaf or XTaint?
 */

#include "DECAF_callback.h"
#include "DECAF_main.h"
#include "utils/Output.h"

//basic stub for plugins
static plugin_interface_t               taint_mem_interface;
static DECAF_Handle mem_write_handle 	= DECAF_NULL_HANDLE;

plugin_interface_t* init_plugin(void);

typedef struct _XT_Taint_Mem{
	uint32_t t_mem_begin;
	uint32_t t_mem_sz;
	uint8_t  t_pattern;
} XT_Taint_Mem;

typedef struct _XT_Mem_Write {
    gva_t       mw_vaddr;
    DATA_TYPE   mw_dt;
} XT_Mem_Write;

static XT_Taint_Mem xt_t_mem = {.t_mem_begin = 0, .t_mem_sz = 0, .t_pattern = 0 };
static XT_Mem_Write xt_mw = {.mw_vaddr = 0, .mw_dt = 0 };

static int enable_taint = 0;
static int total_mw_sz  = 0;

static int taint_mem_init(void);
static void taint_mem_cleanup(void);

static void do_pass_taint_arg(Monitor *mon, const QDict *qdict);
static void load_mem_write_callback(DECAF_Callback_Params* param);

static inline uint8_t get_mw_byte_sz(DATA_TYPE dt);

/*
 * Commands supported by the plugin. Included in plugin_cmds.h
 */
static mon_cmd_t taint_mem_cmds[] = {
		{
		    .name       = "pass_taint_args",
		    .args_type  = "mem_begin:i,mem_sz:i,taint_pattern:i",
		    .mhandler.cmd   = do_pass_taint_arg,
		    .params     = "mem_begin mem_sz taint_pattern",
		    .help       = "pass the memory begin addr, size and pattern"
		},
		{ NULL, NULL, },
};



/*
 * This function registers the plugin_interface with DECAF.
 * The interface is used to register custom commands, let DECAF know which
 * cleanup function to call upon plugin unload, etc,.
 */
plugin_interface_t* init_plugin(void) {
    taint_mem_interface.mon_cmds = taint_mem_cmds;
    taint_mem_interface.plugin_cleanup = &taint_mem_cleanup;

    taint_mem_init();
    return (&taint_mem_interface);
}

/*
 * Register a memory operation (read or write) callback
 */
static int taint_mem_init(void) {
    DECAF_printf("Debug taint memory plugin starts...\n");

    // mem_read_handle = DECAF_register_callback(DECAF_MEM_READ_CB,
    //         &load_mem_read_callback, NULL);
    mem_write_handle = DECAF_register_callback(DECAF_MEM_WRITE_CB,
    		&load_mem_write_callback, NULL);
    if (mem_write_handle == DECAF_NULL_HANDLE) {
        DECAF_printf(
                "Could not register for memory operation events\n");
    }

    return 0;
}

/*
 * This function is invoked when the plugin is unloaded.
 */
static void taint_mem_cleanup(void) {
    DECAF_printf("Bye world\n");
    /*
     * Unregister for the taint memory callback and exit
     */
    if(mem_write_handle != DECAF_NULL_HANDLE) {
        // DECAF_unregister_callback(DECAF_MEM_READ_CB, mem_opera_handle);
    	DECAF_unregister_callback(DECAF_MEM_WRITE_CB, mem_write_handle);
        mem_write_handle = DECAF_NULL_HANDLE;

        // Currently not use
        // if(taint_mem_bitmap != NULL){
        // 	free(taint_mem_bitmap);
        // 	taint_mem_bitmap = NULL;
        // }
    }
}

void do_pass_taint_arg(Monitor *mon, const QDict *qdict)
{
    uint32_t mem_begin = 0;
    uint32_t mem_sz    = 0;
    uint8_t  pattern   = 0;

    if(qdict != NULL) {
        mem_begin = qdict_get_int(qdict, "mem_begin");
        mem_sz    = qdict_get_int(qdict, "mem_sz");
        pattern   = qdict_get_int(qdict, "taint_pattern");
        DECAF_printf("taint target memory: addr: %x sz: %d pattern: %x\n",
                mem_begin, mem_sz, pattern);

        xt_t_mem.t_mem_begin    = mem_begin;
        xt_t_mem.t_mem_sz       = mem_sz;
        xt_t_mem.t_pattern      = pattern;

        enable_taint = 1;
    }
}

/**
 * Handle when Decaf memory write callback is active
 */
static void load_mem_write_callback(DECAF_Callback_Params* param)
{
    if(enable_taint) {
        xt_mw.mw_vaddr = param->mw.vaddr;
        xt_mw.mw_dt    = param->mw.dt;

        // Is mem write buf in the target taint buffer
        uint8_t mw_byte_sz = get_mw_byte_sz(xt_mw.mw_dt);
        if(xt_mw.mw_vaddr >= xt_t_mem.t_mem_begin &&
           (xt_mw.mw_vaddr + mw_byte_sz) <= (xt_t_mem.t_mem_begin + xt_t_mem.t_mem_sz) ) {
            total_mw_sz += mw_byte_sz;
            DECAF_printf("memory write: addr: %x, size: %d bytes\n", xt_mw.mw_vaddr, mw_byte_sz);
            DECAF_printf("total memory write sz: %d\n", total_mw_sz);
        }
    }
}

static inline uint8_t get_mw_byte_sz(DATA_TYPE dt)
{
	uint8_t mw_byte_sz = 0;
	switch(dt){
		case DECAF_BYTE:
			mw_byte_sz = 1;
			break;
		case DECAF_WORD:
			mw_byte_sz = 2;
			break;
		case DECAF_LONG:
			mw_byte_sz = 4;
			break;
		case DECAF_QUAD:
			mw_byte_sz = 8;
			break;
		default:
			break;
	}

	return mw_byte_sz;
}
