/*
 * xt_log_ir.c
 */

#include "monitor.h" // For default_mon
#include "shared/xtaint/xt_log.h"
#include "shared/xtaint/xt_log_ir.h"
#include "shared/xtaint/xt_flag.h"
#include "shared/tainting/taint_memory.h"

#ifdef CONFIG_TCG_XTAINT

int XRAYTAINT_DEBUG = 1;

int xt_enable_log_ir = 0;
int xt_do_log_ir(Monitor *mon, const QDict *qdict, QObject **ret_data){
    if (!taint_tracking_enabled)
        monitor_printf(default_mon, "Ignored, taint tracking is disabled\n");
    else {
        CPUState *env;
        DECAF_stop_vm();
        env = cpu_single_env ? cpu_single_env : first_cpu;
        xt_enable_log_ir = qdict_get_bool(qdict, "load");
        DECAF_start_vm();
        tb_flush(env);
        monitor_printf(default_mon, "XRay Taint log ir changed -> %s\n",
                xt_enable_log_ir ? "ON " : "OFF");
    }
    return 0;
}

// Instrument XT ir
inline void XT_log_ir(TCGv srcShadow, TCGv src, TCGv dst, uint32_t flag)
{
	tcg_gen_XT_log_ir_i32(srcShadow, src, dst, flag);
}

// Instrument XRayTaint mark
inline void XT_mark(TCGv_i32 flag, TCGv_i32 val1, TCGv_i32 val2)
{
	tcg_gen_XT_mark(flag, val1, val2);
}

void XT_debug_empty(){}

// Write both src and dst temporaries
void XT_write_tmp()
{
	register int ebp asm("ebp");
	unsigned int offset = 0x8;

	uint32_t *src_val = (uint32_t*)(ebp + offset);
	uint32_t *src_addr = (uint32_t*)(ebp + offset + 4);
	uint32_t *src_flag = (uint32_t*)(ebp + offset + 8);

	*(uint32_t *)xt_curr_record = *src_flag;
	xt_curr_record += 4;

	*(uint32_t *)xt_curr_record = *src_addr;
	xt_curr_record += 4;

	*(uint32_t *)xt_curr_record = *src_val;
	xt_curr_record += 4;

	xt_curr_pool_sz -= 12;
	if(xt_curr_pool_sz < XT_POOL_THRESHOLD){
		xt_flushFile(xt_log);
		xt_curr_record = xt_pool;
		xt_curr_pool_sz = XT_MAX_POOL_SIZE;
	}
}

// How many temporaries have been written
unsigned int num_tmp = 0;

// Write source temporary into temporary buffer
void XT_write_src_tmp()
{
	register int ebp asm("ebp");
	unsigned int offset = 0x10;
	uint32_t * prev_flag;

	uint32_t *src_val = (uint32_t*)(ebp + offset);
	uint32_t *src_addr = (uint32_t*)(ebp + offset + 4);
	uint32_t *src_flag = (uint32_t*)(ebp + offset + 8);

	// if previous tmp flag is a dst flag, reset the tmp pool
	// Indicating a new IR instrument
	prev_flag = xt_curr_pos - 3;
	if(xt_curr_pos != xt_pool &&
	   XT_decode_TmpEncode(*prev_flag) >= IR_FIRST_DESTINATION){
		// reset the temporary buffer
		xt_curr_pos = xt_tmp_buf;
		memset(xt_tmp_buf, 0x0, sizeof(uint32_t)*XT_BUF_POOL_SZ);
		num_tmp = 0;
	}

	// debug
	// *xt_curr_pos = XT_decode_IREncode(*src_flag);
	*xt_curr_pos = *src_flag;
	xt_curr_pos++;
	*xt_curr_pos = *src_addr;
	xt_curr_pos++;
	*xt_curr_pos = *src_val;
	xt_curr_pos++;

	num_tmp++;
}

// Write destination temporary into temporary buffer
void XT_write_dst_tmp()
{
	register int ebp asm("ebp");
	unsigned int offset = 0x10;
	uint32_t tmpEncode = 0;
	uint32_t *src_tmp_begin;

	uint32_t *dst_val = (uint32_t*)(ebp + offset);
	uint32_t *dst_addr = (uint32_t*)(ebp + offset + 4);
	uint32_t *dst_flag = (uint32_t*)(ebp + offset + 8);

	// debug
	// *xt_curr_pos = XT_decode_IREncode(*dst_flag);
	*xt_curr_pos = *dst_flag;
	xt_curr_pos++;
	*xt_curr_pos = *dst_addr;
	xt_curr_pos++;
	*xt_curr_pos = *dst_val;
	xt_curr_pos++;

	num_tmp++;

	// debug
	tmpEncode = XT_decode_TmpEncode(*dst_flag);
	src_tmp_begin = XT_search_src_tmp(tmpEncode);
	XT_flush_pair_rec(src_tmp_begin, dst_flag, dst_addr, dst_val);

//	if(tmpEncode == IR_FIRST_DESTINATION){
//		// case num_tmp is 2:
//		// 	indicating <1st src, 1st dst>
//		// case num_tmp is 3:
//		//	indicating <1st src, 2nd src, 1st dst, do nothing
//		if(num_tmp == 2)
//			XT_flush_one_rec_pool();
//		else if(num_tmp == 3){}
//		else{
//			fprintf(stderr, "IR_FIRST_DESTINATION: number of temporaries error, abort\n");
//			abort();
//		}
//	} else if(tmpEncode == IR_SECOND_DESTINATION){
//		if(num_tmp == 2)
//			XT_flush_one_rec_pool();
//		else if(num_tmp == 4)
//			XT_flush_two_rec_pool();
//		else{
//			fprintf(stderr, "IR_SECOND_DESTINATION: number of temporaries error, abort\n");
//			abort();
//		}
//	} else{
//		fprintf(stderr, "Error destination encode, abort\n");
//		abort();
//	}

//	switch(tmpEncode){
//		case IR_FIRST_DESTINATION:
//			// case num_tmp is 2:
//			// 	indicating <1st src, 1st dst>
//			// case num_tmp is 3:
//			//	indicating <1st src, 2nd src, 1st dst, do nothing
//			switch(num_tmp){
//				case 2:
//					XT_flush_one_rec_pool();
//					break;
//				case 3:
//				case 4:
//				case 5:
//				case 6:
//				case 7:
//					break;
//				default:
//					fprintf(stderr, "IR_FIRST_DESTINATION: number of temporaries error, abort\n");
//					abort();
//			}
//			break;
//		case IR_SECOND_DESTINATION:
//			switch(num_tmp){
//				case 2:
//					XT_flush_one_rec_pool();
//					break;
//				case 4:
//					XT_flush_two_rec_pool();
//					break;
//				default:
//					fprintf(stderr, "IR_FIRST_DESTINATION: number of temporaries error, abort\n");
//					abort();
//			}
//			break;
//		default:
//			fprintf(stderr, "error destination tmp encode\n");
//			break;
//	}
}

void XT_write_src_dst_tmp()
{
	register int ebp asm("ebp");
	unsigned int offset = 0x10;
	uint32_t tmpEncode = 0;

    uint32_t *dst_val = (uint32_t *) (ebp + offset);
    uint32_t *dst_addr = (uint32_t *) (ebp + offset + 4);
    uint32_t *dst_flag = (uint32_t *) (ebp + offset + 8);

    uint32_t *src_val = (uint32_t *) (ebp + offset + 12);
    uint32_t *src_addr = (uint32_t *) (ebp + offset + 16);
    uint32_t *src_flag = (uint32_t *) (ebp + offset + 20);

    *(uint32_t *)xt_curr_record = XT_decode_IREncode(*src_flag);
    xt_curr_record += 4;
    *(uint32_t *) xt_curr_record = *src_addr;
    xt_curr_record += 4;
    *(uint32_t *) xt_curr_record = *src_val;
    xt_curr_record += 4;

    *(uint32_t *)xt_curr_record = XT_decode_IREncode(*dst_flag);
    xt_curr_record += 4;
    *(uint32_t *) xt_curr_record = *dst_addr;
    xt_curr_record += 4;
    *(uint32_t *) xt_curr_record = *dst_val;
    xt_curr_record += 4;

	// If hit threash, flush to file and reset
	xt_curr_pool_sz -= 24;
	if(xt_curr_pool_sz < XT_POOL_THRESHOLD){
		xt_flushFile(xt_log);
		xt_curr_record = xt_pool;
		xt_curr_pool_sz = XT_MAX_POOL_SIZE;
	}
}

void XT_write_mark()
{
	register int ebp asm("ebp");
	unsigned int offset = 0x18;

	uint32_t *val2 = (uint32_t*)(ebp + offset);
	uint32_t *val1 = (uint32_t*)(ebp + offset + 4);
	uint32_t *flag = (uint32_t*)(ebp + offset + 8);

	// special handing for Call mark
	if(*flag == XT_INSN_CALL || \
	   *flag == XT_INSN_RET)
		*val1 -= 4;

	*(uint32_t *)xt_curr_record = *flag;
	xt_curr_record += 4;

	*(uint32_t *)xt_curr_record = *val1;
	xt_curr_record += 4;

	*(uint32_t *)xt_curr_record = *val2;
	xt_curr_record += 4;

	xt_curr_pool_sz -= 12;
	if(xt_curr_pool_sz < XT_POOL_THRESHOLD){
		xt_flushFile(xt_log);
		xt_curr_record = xt_pool;
		xt_curr_pool_sz = XT_MAX_POOL_SIZE;
	}
}

void XT_write_insn_mark()
{
	register int ebp asm("ebp");
	unsigned int offset = 0x18;

	uint32_t *val2 = (uint32_t*)(ebp + offset);
	uint32_t *val1 = (uint32_t*)(ebp + offset + 4);
	uint32_t *flag = (uint32_t*)(ebp + offset + 8);

	// special handing for Call mark
	if(*flag == XT_INSN_CALL || \
	   *flag == XT_INSN_RET)
		*val1 -= 4;

	*(uint32_t *)xt_curr_record = *flag;
	xt_curr_record += 4;

	*(uint32_t *)xt_curr_record = *val1;
	xt_curr_record += 4;

	*(uint32_t *)xt_curr_record = *val2;
	xt_curr_record += 4;

	xt_curr_pool_sz -= 12;
	if(xt_curr_pool_sz < XT_POOL_THRESHOLD){
		xt_flushFile(xt_log);
		xt_curr_record = xt_pool;
		xt_curr_pool_sz = XT_MAX_POOL_SIZE;
	}
}

// flush the one record in temporary buffer into xt pool
void XT_flush_one_rec_pool()
{
	uint32_t *idx = xt_tmp_buf;
	int i = 0;

	for(; i < 6; i++){
		*(uint32_t *)xt_curr_record = *idx;
		idx++;
		xt_curr_record += 4;
	}

	// If hit threash, flush to file and reset
	xt_curr_pool_sz -= 24;
	if(xt_curr_pool_sz < XT_POOL_THRESHOLD){
		xt_flushFile(xt_log);
		xt_curr_record = xt_pool;
		xt_curr_pool_sz = XT_MAX_POOL_SIZE;
	}

	// reset the temporary buffer
	xt_curr_pos = xt_tmp_buf;
	memset(xt_tmp_buf, 0x0, sizeof(uint32_t)*12);
	num_tmp = 0;
}

// flush the two records in temporary buffer into xt pool
void XT_flush_two_rec_pool()
{
	uint32_t *idx;
	int i;

	// flush 1st rec source
	idx = xt_tmp_buf;
	for(i = 0; i < 3; i++){
		*(uint32_t *)xt_curr_record = *idx;
		idx++;
		xt_curr_record += 4;
	}

	// flush 1st rec destination
	idx = xt_tmp_buf + 6;
	for(i = 0; i < 3; i++){
		*(uint32_t *)xt_curr_record = *idx;
		idx++;
		xt_curr_record += 4;
	}

	// flush 2nd rec source
	idx = xt_tmp_buf + 3;
	for(i = 0; i < 3; i++){
		*(uint32_t *)xt_curr_record = *idx;
		idx++;
		xt_curr_record += 4;
	}

	// flush 2st rec destination
	idx = xt_tmp_buf + 9;
	for(i = 0; i < 3; i++){
		*(uint32_t *)xt_curr_record = *idx;
		idx++;
		xt_curr_record += 4;
	}

	// If hit threash, flush to file and reset
	xt_curr_pool_sz -= 48;
	if(xt_curr_pool_sz < XT_POOL_THRESHOLD){
		xt_flushFile(xt_log);
		xt_curr_record = xt_pool;
		xt_curr_pool_sz = XT_MAX_POOL_SIZE;
	}

	// reset the temporary buffer
	xt_curr_pos = xt_tmp_buf;
	memset(xt_tmp_buf, 0x0, sizeof(uint32_t)*12);
	num_tmp = 0;
}

void XT_flush_pair_rec(uint32_t *src, uint32_t *dst_flag, uint32_t *dst_addr, uint32_t *dst_val)
{
	int i = 0;
	// flush src tmp
	*(uint32_t *)xt_curr_record = XT_decode_IREncode(*src);
	src++;
	xt_curr_record += 4;
	// flush src addr and val
	for(; i < 2; i++){
		*(uint32_t *)xt_curr_record = *src;
		src++;
		xt_curr_record += 4;
	}

	// flush dst tmp
	*(uint32_t *)xt_curr_record = XT_decode_IREncode(*dst_flag);
	xt_curr_record += 4;
	*(uint32_t *)xt_curr_record = *dst_addr;
	xt_curr_record += 4;
	*(uint32_t *)xt_curr_record = *dst_val;
	xt_curr_record += 4;

	// If hit threash, flush to file and reset
	xt_curr_pool_sz -= 24;
	if(xt_curr_pool_sz < XT_POOL_THRESHOLD){
		xt_flushFile(xt_log);
		xt_curr_record = xt_pool;
		xt_curr_pool_sz = XT_MAX_POOL_SIZE;
	}
}

// Based on given destination temporarty encode,
// i.e., IR_FIRST_DESTINATION,
// Searches its corresponding source temporary in the tmp pool
uint32_t *XT_search_src_tmp(uint32_t dst_tmp_encode)
{
	uint32_t *curr_field = xt_tmp_buf;
	int sz = 0;
	for(; sz < XT_BUF_POOL_SZ; sz++){
		if(XT_cmp_tmp_encode(XT_decode_TmpEncode(*curr_field), dst_tmp_encode) )
			return curr_field;
		// !!! It must be flag field all the time
		// Otherwise addr or val field might be same as IR_SECOND_SROUCE,
		// Result in an false positive
		curr_field += 3;
	}
	fprintf(stderr, "error not found corresponding source temporary encode\n");
	abort();
}

inline int XT_cmp_tmp_encode(uint32_t src_encode, uint32_t dst_encode)
{
	switch(dst_encode){
		case IR_FIRST_DESTINATION:
			if(src_encode == IR_FIRST_SOURCE)
				return 1;
			break;
		case IR_SECOND_DESTINATION:
			if(src_encode == IR_SECOND_SOURCE)
				return 1;
			break;
		case IR_THIRD_DESTINATION:
			if(src_encode == IR_THIRD_SOURCE)
				return 1;
			break;
		case IR_FOURTH_DESTINATION:
			if(src_encode == IR_FOURTH_SOURCE)
				return 1;
			break;
		case IR_FIFTH_DESTINATION:
			if(src_encode == IR_FIFTH_SOURCE)
				return 1;
			break;
		case IR_SIXTH_DESTINATION:
			if(src_encode == IR_SIXTH_SOURCE)
				return 1;
			break;
		default:
			fprintf(stderr, "error incorrect destination temparary encode\n");
			break;
	}
	return 0;
}

// Encode IREncode and TmpEncode into flag
// TmpEncode:
//	- 1st src, 2nd src, 1st destination, 2nd destination, normal tmp
//	requires 3 bit to encode information
// IREncode:
//	- encodes of IRs, there are arround thirties
//	- requires rest of bits
inline uint32_t XT_encode_flag(uint32_t IREncode, uint32_t TmpEncode)
{
	uint32_t flag;
	flag = (IREncode << TMP_ENCODE_POS) | TmpEncode;
	return flag;
}

inline uint32_t XT_decode_TmpEncode(uint32_t flag)
{
	// return flag & TMP_MASK;
	return flag & 0xf;
}

inline uint32_t XT_decode_IREncode(uint32_t flag)
{
	return flag >> TMP_ENCODE_POS;
}
#endif /* CONFIG_TCG_XTAINT */

