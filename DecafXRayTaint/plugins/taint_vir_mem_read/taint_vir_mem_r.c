#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"
#include "tainting/taintcheck_opt.h"

#include <assert.h>
#include <stdbool.h>

//basic stub for plugins
static plugin_interface_t taint_mem_interface;
static DECAF_Handle mem_read_handle 	= DECAF_NULL_HANDLE;
static DECAF_Handle mem_write_handle 	= DECAF_NULL_HANDLE;

typedef struct _XT_Taint_Mem{
	uint32_t addr;
	uint32_t taint_sz;
	uint8_t pattern;
} XT_Taint_Mem;

typedef struct _XT_Mem_Write{
	gva_t mw_vaddr;
	DATA_TYPE mw_dt;
} XT_Mem_Write;

plugin_interface_t* init_plugin(void);
static int taint_mem_init(void);
static void load_mem_read_callback(DECAF_Callback_Params* param);
static void load_mem_write_callback(DECAF_Callback_Params* param);
static bool comp_taint_range(XT_Mem_Write *mw, XT_Taint_Mem *tm, XT_Taint_Mem *rtm);
static void set_taint_range_bitmap(uint32_t addr, uint32_t byte_sz);
static bool test_taint_range_bitmap(uint32_t addr, uint32_t byte_sz);
static bool is_range_taint(uint32_t addr, uint32_t byte_sz);
static inline uint8_t get_mw_byte_size(DATA_TYPE dt);

static inline void set_bitmap(uint8_t *taint_mem_bitmap, uint32_t bit_idx);
static inline int test_bitmap(uint8_t *taint_mem_bitmap, uint32_t bit_index);

static const int ADDR_OFFSET = 1;
static const int BYTE_TO_BIT = 8;

static int is_taint = 0;

static uint8_t *taint_mem_bitmap = NULL;

static XT_Taint_Mem xt_taint_mem = { .addr = 0, .taint_sz = 0, .pattern = 0 };
static XT_Mem_Write xt_mw = { .mw_vaddr = 0, .mw_dt = 0 };

static int total_taint_sz = 0;

static uint32_t taint_addr = 0;
static uint32_t taint_sz = 0;
static uint8_t taint_pattern = 0;
// static uint32_t offset = 12;
static uint32_t offset = 44;
// static uint32_t offset = 0;

void do_pass_taint_arg(Monitor *mon, const QDict *qdict)
{
    uint32_t mem_addr = 0;
    uint32_t mem_size = 0;
    uint8_t pattern = 0;

    if(qdict != NULL){
        mem_addr = qdict_get_int(qdict, "mem_addr");
        mem_size = qdict_get_int(qdict, "mem_size");
        pattern = qdict_get_int(qdict, "taint_pattern");
        DECAF_printf("The mem addr: %x and mem_size: %d, taint_pattern: %x\n", \
                mem_addr, mem_size, pattern);

        // taint_addr = mem_addr;
        // taint_sz = mem_size;
        // taint_pattern = pattern;

        xt_taint_mem.addr 		= mem_addr;
        xt_taint_mem.taint_sz 	= mem_size;
        xt_taint_mem.pattern 	= pattern;

        if(xt_taint_mem.addr > 0 && xt_taint_mem.taint_sz > 0){
        	// Init bit array
        	if(taint_mem_bitmap != NULL)
        		free(taint_mem_bitmap);

        	uint32_t num_byte = xt_taint_mem.taint_sz / BYTE_TO_BIT + 1;
        	taint_mem_bitmap = (uint8_t*)calloc(num_byte, sizeof(uint8_t) );
        	DECAF_printf("Initialized bit array of taint memory...\n");

        	// Set is_taint
        	is_taint = true;
        }
    }
}

void do_taint_memory(uint32_t addr, uint32_t sz, uint8_t pattern){
	uint32_t begin_addr = 0;

	if(addr > 0 && sz > 0){
		// Only if all bits of taint range are not tainted;
	    // otherwise, any bit in the range is not tainted, re-taint
	    // the whole range again
		if( test_taint_range_bitmap(addr, sz) == false ){
			uint8_t taint_source[sz];
			memset(taint_source, pattern, sz);
			if(taintcheck_taint_virtmem(addr, sz, taint_source) != 0){
				DECAF_printf("Fail to taint guest OS memory!\n");
			}else{
//				DECAF_printf("Successfully to taint guest OS memory!\n");
				// set corresponding bitmap range
				set_taint_range_bitmap(addr, sz);

				total_taint_sz += sz;
				DECAF_printf("Total tainted bytes: %d\n", total_taint_sz);
			}
		}else {
//		    DECAF_printf("Target tainting range had been tainted already...\n");
		}
	}else
		DECAF_printf("error: target taint memory range is invalid\n");

//	if(sz > 0){
//		memset(taint_source, pattern, sz);
//		begin_addr = addr - offset;
//		begin_addr = addr;
//		if (taintcheck_taint_virtmem(begin_addr, sz, taint_source) != 0) {
//			DECAF_printf("Fail to taint guest OS memory!\n");
//		} else {
//			DECAF_printf("Successfully to taint guest OS memory!\n");
//			taint_addr = 0;
//			taint_sz = 0;
//			taint_pattern = 0;
//		}
//	}
}

static void load_mem_read_callback(DECAF_Callback_Params* param) {
    if(param->mr.vaddr == taint_addr && taint_addr != 0){
        do_taint_memory(taint_addr, taint_sz, taint_pattern);
    }
}

/**
 * Handle when Decaf memory write callback is active
 */
static void load_mem_write_callback(DECAF_Callback_Params* param) {
	if(is_taint){
		XT_Taint_Mem xt_rtm = { .addr = 0, .taint_sz = 0, .pattern = 0 };

		xt_mw.mw_vaddr	= param->mw.vaddr;
		xt_mw.mw_dt 	= param->mw.dt;

		if(comp_taint_range(&xt_mw, &xt_taint_mem, &xt_rtm) ){
			uint8_t mw_byte_sz = get_mw_byte_size(xt_mw.mw_dt);
//			DECAF_printf("memory write: addr: %x, size: %d bytes\n", xt_mw.mw_vaddr, mw_byte_sz);
//			DECAF_printf("computed range: addr: %x, size: %d bytes\n", xt_rtm.addr, xt_rtm.taint_sz);

			if(xt_rtm.addr >= xt_mw.mw_vaddr &&
				xt_rtm.addr + xt_rtm.taint_sz <= xt_mw.mw_vaddr + mw_byte_sz) {
				do_taint_memory(xt_rtm.addr, xt_rtm.taint_sz, xt_rtm.pattern);
			}
		}

		// Is whole target range tainted?
		if(is_range_taint(xt_taint_mem.addr, xt_taint_mem.taint_sz) ){
			is_taint = false;
			if(taint_mem_bitmap != NULL){
				free(taint_mem_bitmap);
				taint_mem_bitmap = NULL;
			}
		}
	}

    // if(param->mw.vaddr == taint_addr && taint_addr != 0){
    //     do_taint_memory(taint_addr, taint_sz, taint_pattern);
    // }
}

/*
 * Register a memory operation (read or write) callback
 */
static int taint_mem_init(void) {
    DECAF_printf("Taint memory plugin starts...\n");

    // mem_read_handle = DECAF_register_callback(DECAF_MEM_READ_CB,
    //         &load_mem_read_callback, NULL);
    mem_write_handle = DECAF_register_callback(DECAF_MEM_WRITE_CB,
    		&load_mem_write_callback, NULL);
    if (mem_write_handle == DECAF_NULL_HANDLE) {
        DECAF_printf(
                "Could not register for memory operation events\n");
    }
    return (0);
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

        if(taint_mem_bitmap != NULL){
        	free(taint_mem_bitmap);
        	taint_mem_bitmap = NULL;
        }
    }
}

/*
 * Commands supported by the plugin. Included in plugin_cmds.h
 */
static mon_cmd_t taint_mem_cmds[] = {
		{
		    .name       = "pass_taint_args",
		    .args_type  = "mem_addr:i,mem_size:i,taint_pattern:i",
		    .mhandler.cmd   = do_pass_taint_arg,
		    .params     = "mem_addr mem_size taint_pattern",
		    .help       = "pass the begin addr,size and pattern tainting memory"
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
 * Given the memory write range and the target taint range,
 * computes the real taint range that intersects of two
 */
static bool
comp_taint_range(XT_Mem_Write *mw, XT_Taint_Mem *tm, XT_Taint_Mem *rtm)
{
	bool hasIntersect 	= false;
	gva_t res_addr 		= 0;
	uint8_t res_sz 		= 0;

	if(mw && tm && rtm){
		// Debug
//		if(mw->mw_vaddr >= 0xbffff7a4 &&
//			mw->mw_vaddr <= 0xbffff7a4 + 8)
//			DECAF_printf("Debug: write target memory\n");

		uint8_t mw_byte_sz = get_mw_byte_size(mw->mw_dt);
		gva_t mw_b_addr = mw->mw_vaddr;
		gva_t mw_e_addr = mw->mw_vaddr + mw_byte_sz - ADDR_OFFSET;

		gva_t tm_b_addr = tm->addr;
		gva_t tm_e_addr = tm->addr + tm->taint_sz - ADDR_OFFSET;

		// No intersection
		if(mw_e_addr < tm_b_addr || tm_e_addr < mw_b_addr)
			return hasIntersect;
		else{
		// Has intersection
			if(mw_b_addr <= tm_b_addr){
				// Intersection
				if(mw_e_addr <= tm_e_addr){
					res_addr = tm_b_addr;
					res_sz   = mw_e_addr - tm_b_addr + ADDR_OFFSET;
				} else{ // mw range contains tm range
					res_addr = tm_b_addr;
					res_sz   = tm->taint_sz;
				}
			}else{ // mw_b_addr > tm_b_addr
				if(tm_e_addr <= mw_e_addr){
					res_addr = mw_b_addr;
					res_sz   = tm_e_addr - mw_b_addr + ADDR_OFFSET;
				}else{ // tm range cantains mw.range
					res_addr = mw_b_addr;
					res_sz   = mw_byte_sz;
				}
			}
			hasIntersect = true;
		}

		rtm->addr 		= res_addr;
		rtm->taint_sz 	= res_sz;
		rtm->pattern 	= tm->pattern;
	}else
		DECAF_printf("error, taint memory struct pointer is null\n");

	return hasIntersect;
}

/*
 * Given the target taint range: <begin address, size>,
 * determines if the corresponding range in bitmap has been
 * tainted (1) or not (0)
 *
 * If all bits in the range has been tainted, the whole range
 * has been tainted.
 *
 * return:
 * 		false: all bits in the range has Not been tainted (all 0s)
 * 		true: else
 */
static bool test_taint_range_bitmap(uint32_t addr, uint32_t byte_sz)
{
	bool hasTaint = false;

	if(addr < xt_taint_mem.addr){
		DECAF_printf("error, test_taint_range_bitmap: addr is smaller target taint memory begin addr\n");
		return true;
	}

	if(byte_sz == 0){
		DECAF_printf("error, test_taint_range_bitmap: byte size is zero\n");
		return true;
	}

	uint32_t begin_bit_idx = addr - xt_taint_mem.addr;
	uint32_t byte_idx = 0;

	// Only if all bits are true (tainted), return true;
	// Otherwise, return false
	for(; byte_idx < byte_sz; byte_idx++){
	    hasTaint = test_bitmap(taint_mem_bitmap, begin_bit_idx + byte_idx);

		// if(test_bitmap(taint_mem_bitmap, begin_bit_idx + byte_idx) ){
		// 	hasTaint = true;
		// 	break;
		// }
	}

	return hasTaint;
}

static void set_taint_range_bitmap(uint32_t addr, uint32_t byte_sz)
{
	if(addr >= xt_taint_mem.addr && byte_sz > 0){
		uint32_t begin_bit_idx = addr - xt_taint_mem.addr;
		uint32_t byte_idx = 0;
		for(; byte_idx < byte_sz; byte_idx++){
			set_bitmap(taint_mem_bitmap, begin_bit_idx + byte_idx);
		}
	} else
		DECAF_printf("error, set_taint_range_bitmap: invalid addr or byte_sz\n");
}

/*
 * Is the whole range: <addr, byte_sz> has been tainted in
 * corresponding bitmap
 *
 * return:
 * 		true/false
 */
static bool is_range_taint(uint32_t addr, uint32_t byte_sz)
{
	bool hasTaint = true;

	if(addr >= xt_taint_mem.addr && byte_sz >0 ){
		uint32_t begin_bit_idx = addr - xt_taint_mem.addr;
		uint32_t byte_idx = 0;
		for(; byte_idx < byte_sz; byte_idx++){
			if( test_bitmap(taint_mem_bitmap, begin_bit_idx + byte_idx) == 0){
				hasTaint = false;
				break;
			}
		}
	} else
		DECAF_printf("error, is_range_taint: invalid addr or byte_sz\n");

	return hasTaint;
}

/*
 * Given a bitmap and the bit index, return if the bit of the index
 * is 0 or 1
 */
static inline int test_bitmap(uint8_t *taint_mem_bitmap, uint32_t bit_index)
{
	if(taint_mem_bitmap == NULL){
		DECAF_printf("error: taint memory bitmap is empty\n");
		return 1;
	}

	if( (taint_mem_bitmap[bit_index / BYTE_TO_BIT] & (1 << (bit_index % BYTE_TO_BIT) ) ) != 0 )
		return 1;
	else
		return 0;
}

/*
 * Given a bitmap and the bit index, set the bit of the index to 1
 */
static inline void set_bitmap(uint8_t *taint_mem_bitmap, uint32_t bit_idx)
{
	if(taint_mem_bitmap == NULL)
		DECAF_printf("error: set_bitmap: taint memory bitmap is empty\n");
	else
		taint_mem_bitmap[bit_idx / BYTE_TO_BIT] |= 1 << (bit_idx % BYTE_TO_BIT);
}

static inline void print_bitmap(uint8_t *taint_mem_bitmap, uint32_t byte_sz)
{
	if(taint_mem_bitmap){
		DECAF_printf("taint memory bitmap: \n");
		uint32_t byte_idx = 0;
		for(; byte_idx < byte_sz; byte_idx++){
			DECAF_printf("");
		}
	}else
		DECAF_printf("error: print_bitmap, invalid taint memory bitmap\n");
}

static inline uint8_t get_mw_byte_size(DATA_TYPE dt)
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
