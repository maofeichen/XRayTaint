/*
 * xt_main.c
 */
#include "shared/xtaint/xt_log.h"
#include "shared/xtaint/xt_main.h"

#ifdef CONFIG_TCG_XTAINT

static const char *xt_logPath = "/home/xtaint/Workplace/XRayTaint/TestResult/xt_log.txt";

void XT_init(void) {
    if((xt_log = fopen(xt_logPath, "wa") ) == NULL){
            fprintf(stderr, "fail to open xray taint log\n");
    }
    printf("XTaint: start \nXTaint: open file and prepare to log.\n");
}

void XT_clean(void) {
    if(xt_curr_pool_sz < XT_MAX_POOL_SIZE)
         xt_flushFile(xt_log);
    fclose(xt_log);
    printf("XTaint: close file and finish logging\nXTaint: close\n");
}

#endif /* CONFIG_TCG_XTAINT */


