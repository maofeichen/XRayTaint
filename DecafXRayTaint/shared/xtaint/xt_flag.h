/*
 * xt_flag.h
 */

#ifndef XT_FLAG_H_
#define XT_FLAG_H_

// Encode of target register
#define TARGET_ESP 4

// Encode of logging ir flag
#define IR_FIRST_SOURCE 0x1
#define IR_SECOND_SOURCE 0x2
#define IR_FIRST_DESTINATION 0x3
#define IR_SECOND_DESTINATION 0x4
#define IR_NORMAL 0x5

// Encode IR
#define TCG_SHL 0x36


/* Encode global temporary address */
#define G_TEMP_UNKNOWN 0xFFF0
#define G_TEMP_ENV 0xFFF1
#define G_TEMP_CC_OP 0xFFF2
#define G_TEMP_CC_SRC 0xFFF3
#define G_TEMP_CC_DST 0xFFF4
#define G_TEMP_CC_TMP 0xFFF5
#define G_TEMP_EAX 0xFFF6
#define G_TEMP_ECX 0xFFF7
#define G_TEMP_EDX 0xFFF8
#define G_TEMP_EBX 0xFFF9
#define G_TEMP_ESP 0xFFFa
#define G_TEMP_EBP 0xFFFb
#define G_TEMP_ESI 0xFFFc
#define G_TEMP_EDI 0xFFFd

#endif /* XT_FLAG_H_ */
