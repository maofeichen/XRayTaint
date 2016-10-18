/*
 * xt_log_ir.h
 */

#ifndef XT_LOG_IR_H_
#define XT_LOG_IR_H_

#include <inttypes.h>
#include "tcg-op.h"

extern int xt_enable_log_ir;

extern inline void XT_log_ir(TCGv srcShadow, TCGv src, TCGv dst, uint32_t flag);

#endif /* XT_LOG_IR_H_ */
