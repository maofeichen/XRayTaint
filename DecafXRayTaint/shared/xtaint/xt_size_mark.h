/*
 * xt_size_mark.h
 */

#ifndef XT_SIZE_MARK_H_
#define XT_SIZE_MARK_H_

#include "qdict.h"
#include "tcg-op.h"
#include "shared/xtaint/xt_flag.h"

// Enable/disable xraytaint mark
extern int xt_enable_size_mark;
extern int xt_do_size_mark(Monitor *mon, const QDict *qdict, QObject **ret_data);

extern inline int assign_size_flag(uint16_t opc);

#endif /* XT_SIZE_MARK_H_ */
