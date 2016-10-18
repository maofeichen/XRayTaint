/*
 * xt_log_ir.c
 */

#include "shared/xtaint/xt_log_ir.h"

#ifdef CONFIG_TCG_XTAINT

int xt_enable_log_ir = 0;

inline void XT_log_ir(TCGv srcShadow, TCGv src, TCGv dst, uint32_t flag)
{
	tcg_gen_XT_log_ir_i32(srcShadow, src, dst, flag);
}

#endif /* CONFIG_TCG_XTAINT */

