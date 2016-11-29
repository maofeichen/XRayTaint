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
#define TCG_SHR 0x37
#define TCG_SAR 0x38
#define TCG_ROTL 0x39
#define TCG_ROTR 0x3a

#define TCG_ADD_i32 0x3b
#define TCG_SUB_i32 0x3c
#define TCG_MUL_i32 0x3d
#define TCG_DIV_i32 0x3e
#define TCG_DIVU_i32 0x3f
#define TCG_REM_i32 0x40
#define TCG_REMU_i32 0x41
#define TCG_MUL2_i32 0x42
#define TCG_DIV2_DIVU2_i32 0x43

#define TCG_AND_i32 0x44
#define TCG_OR_i32 0x45
#define TCG_XOR_i32 0x46
#define TCG_NOT_i32 0x47
#define TCG_NEG_i32 0x48

#define TCG_EXT8S_i32 0x49
#define TCG_EXT16S_i32 0x4a
#define TCG_EXT8U_i32 0x4b
#define TCG_EXT16U_i32 0x4c

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
