/*
 * xt_log_ir.h
 */

#ifndef XT_LOG_IR_H_
#define XT_LOG_IR_H_

#include <inttypes.h>
#include "qdict.h"
#include "tcg-op.h"

#define TMP_ENCODE_POS 3
#define TMP_MASK 0x7

extern int XRAYTAINT_DEBUG;

// Enable/disable xraytaint log
extern int xt_enable_log_ir;
extern int xt_do_log_ir(Monitor *mon, const QDict *qdict, QObject **ret_data);

// Instument xraytaint log ir
extern inline void XT_log_ir(TCGv srcShadow, TCGv src, TCGv dst, uint32_t flag);

// write log to buffer
extern void XT_debug_empty();
extern void XT_write_tmp();

extern unsigned int num_tmp;
extern void XT_write_src_tmp();
extern void XT_write_dst_tmp();
extern void XT_flush_one_rec_pool();
extern void XT_flush_two_rec_pool();

extern inline uint32_t XT_encode_flag(uint32_t IREncode, uint32_t TmpEncode);
extern inline uint32_t XT_decode_TmpEncode(uint32_t flag);
extern inline uint32_t XT_decode_IREncode(uint32_t flag);

#endif /* XT_LOG_IR_H_ */
