/*
 * xt_log_ir.h
 */

#ifndef XT_LOG_IR_H_
#define XT_LOG_IR_H_

#include <inttypes.h>
#include "qdict.h"
#include "tcg-op.h"

extern int xt_enable_log_ir;
extern int xt_do_log_ir(Monitor *mon, const QDict *qdict, QObject **ret_data);

extern inline void XT_log_ir(TCGv srcShadow, TCGv src, TCGv dst, uint32_t flag);

#endif /* XT_LOG_IR_H_ */