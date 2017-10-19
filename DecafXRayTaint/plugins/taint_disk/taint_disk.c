#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"
#include "tainting/taintcheck_opt.h"

// for BlockDriverState
#include "blockdev.h"
#include "block_int.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

static plugin_interface_t taint_disk_interface;

void do_pass_taint_disk(Monitor *mon, const QDict *qdict);

plugin_interface_t* init_plugin(void);

static int taint_disk_init(void);
static void do_taint_disk(uint32_t sec_no, uint32_t sec_sz, uint32_t offset, uint32_t pattern);
static BlockDriverState* get_bs(void);

void do_pass_taint_disk(Monitor *mon, const QDict *qdict)
{
    uint32_t sec_no   = 0;
    uint32_t sec_size = 0;
    uint32_t offset   = 0;
    uint32_t pattern  = 0;

    if(qdict != NULL){
        sec_no    = qdict_get_int(qdict, "sec_no");
        sec_size  = qdict_get_int(qdict, "sec_sz");
        offset    = qdict_get_int(qdict, "offset");
        pattern   = qdict_get_int(qdict, "taint_pattern");
        DECAF_printf("Taint disk - sec no: %d - sec size: %d - offset: %ud - taint_pattern: %x\n", sec_no, sec_size, offset, pattern);

        if(sec_no && sec_size && pattern) {
          do_taint_disk(sec_no, sec_size, offset, pattern);
        }
    }
}

/*
 * Commands supported by the plugin. Included in plugin_cmds.h
 */
static mon_cmd_t taint_disk_cmds[] = {
		{
		    .name       = "pass_taint_disk_args",
		    .args_type  = "sec_no:i,sec_sz:i,offset:i,taint_pattern:i",
		    .mhandler.cmd   = do_pass_taint_disk,
		    .params     = "sec_no sec_sz offset taint_pattern",
		    .help       = "pass the sector no, sector size, offset and pattern for tainting disk"
		},
};


/*
 * Register a memory operation (read or write) callback
 */
static int taint_disk_init(void) {
    DECAF_printf("Taint disk plugin starts...\n");

    return (0);
}

/*
 * This function is invoked when the plugin is unloaded.
 */
static void taint_disk_cleanup(void) {
    DECAF_printf("Bye world\n");
}

static void do_taint_disk(uint32_t sec_no, uint32_t sec_sz, uint32_t offset, uint32_t pattern)
{
    DECAF_printf("enter do_taint_disk() - sec no: %ud - sec size: %ud - offset: %ud - taint_pattern: %x\n", sec_no, sec_sz, offset, pattern);

    if(pattern == 0) {
      fprintf(stderr, "taint pattern is 0\n");
      return;
    }

    BlockDriverState *bs = get_bs();
    if(bs != NULL) {
      fprintf(stderr, "do_taint_disk(): BlockDriverState: %p "
          "- total sectors: %d "
          "- filename: %s "
          "- devicenmae: %s\n", bs, bs->total_sectors, bs->filename, bs->device_name);

      int bm_offset;
      uint64_t prev_index, curr_index;
      prev_index = sec_no * 8 + offset / 64;
      for(bm_offset = offset ; bm_offset < sec_sz + offset; bm_offset += 4) {
//        fprintf(stderr, "do_taint_disk() -> taintcheck_taint_disk()\n");
        curr_index = sec_no * 8 + bm_offset / 64;
        taintcheck_taint_disk(curr_index, pattern, bm_offset & 63, 4/*size*/, (void*)bs);
        if(prev_index != curr_index) {
          debug_disk_record(prev_index, bs);
        }
        prev_index = curr_index;
      }
      debug_disk_record(curr_index, bs);

    } else {
      fprintf(stderr, "error: do_taint_disk() - can't find BlockDriverState\n");
    }
}

/*
 * get the BlockDriverState *bs that is required by the taintcheck_taint_disk()
 */
static BlockDriverState* get_bs()
{
    /*
    DriveInfo *dinfo;
//	  int index = 0;
    QTAILQ_FOREACH(dinfo, &drives, next) {
        if (dinfo->type == IF_DEFAULT || dinfo->type == IF_SCSI || dinfo->type == IF_IDE ) {
//          DECAF_bdrv_open(index,(void *)dinfo->bdrv);
//          ++index;
          fprintf(stderr, "get_bs(): BlockDriverState: %p\n", dinfo->bdrv);
          opaque = (void *)dinfo->bdrv;
          return 1;
        }
    }

    return 0;
    */
    BlockDriverState *bs = bdrv_find("ide0-hd0");
    fprintf(stderr, "bdrv_find() bs: %p\n", bs);
    return bs;
}

/*
 * This function registers the plugin_interface with DECAF.
 * The interface is used to register custom commands, let DECAF know which
 * cleanup function to call upon plugin unload, etc,.
 */
plugin_interface_t* init_plugin(void) {
//    taint_mem_interface.mon_cmds = taint_mem_cmds;
//    taint_mem_interface.plugin_cleanup = &taint_mem_cleanup;

//    taint_mem_init();
//    return (&taint_mem_interface);

    taint_disk_interface.mon_cmds       = taint_disk_cmds;
    taint_disk_interface.plugin_cleanup = &taint_disk_cleanup;
    taint_disk_init();

    return (&taint_disk_interface);
}
