/*
 * xt_insn_mark.h
 */

#ifndef XT_INSN_MARK_H_
#define XT_INSN_MARK_H_

#include "qdict.h"
#include "tcg-op.h"

// Enable/disable xraytaint mark
extern int xt_enable_insn_mark;
extern int xt_do_insn_mark(Monitor *mon, const QDict *qdict, QObject **ret_data);

#endif /* XT_INSN_MARK_H_ */
