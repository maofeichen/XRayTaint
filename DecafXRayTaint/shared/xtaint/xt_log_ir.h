/*
 * xt_log_ir.h
 */

#ifndef XT_LOG_IR_H_
#define XT_LOG_IR_H_

#include <inttypes.h>
#include "qdict.h"
#include "tcg-op.h"

#define TMP_ENCODE_POS 4
#define TMP_MASK 15

extern int XRAYTAINT_DEBUG;

// Enable/disable xraytaint log
extern int xt_enable_log_ir;
extern int xt_do_log_ir(Monitor *mon, const QDict *qdict, QObject **ret_data);

// Instument xraytaint log ir
extern inline void XT_log_ir(TCGv srcShadow, TCGv src, TCGv dst, uint32_t flag);
// Instrument xraytaint mark
extern inline void XT_mark(TCGv_i32 flag, TCGv_i32 val1, TCGv_i32 val2);

// write log to buffer
extern void XT_debug_empty();
extern void XT_write_tmp();

extern unsigned int num_tmp;
extern void XT_write_src_tmp();
extern void XT_write_dst_tmp();
extern void XT_write_src_dst_tmp();

extern void XT_write_mark();
// Debug write insn mark
extern void XT_write_insn_mark();

extern void XT_flush_one_rec_pool();
extern void XT_flush_two_rec_pool();
extern void XT_flush_pair_rec(uint32_t *src, uint32_t *dst_flag, uint32_t *dst_addr, uint32_t *dst_val);
extern uint32_t *XT_search_src_tmp(uint32_t dst_tmp_encode);
extern inline int XT_cmp_tmp_encode(uint32_t src_encode, uint32_t dst_encode);

extern inline uint32_t XT_encode_flag(uint32_t IREncode, uint32_t TmpEncode);
extern inline uint32_t XT_decode_TmpEncode(uint32_t flag);
extern inline uint32_t XT_decode_IREncode(uint32_t flag);

#endif /* XT_LOG_IR_H_ */
